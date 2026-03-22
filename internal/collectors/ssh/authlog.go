package ssh

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

var (
	reFailed   = regexp.MustCompile(`Failed password for (invalid user )?(\S+) from (\S+) port (\d+)`)
	reInvalid  = regexp.MustCompile(`Invalid user (\S+) from (\S+) port (\d+)`)
	reAccepted = regexp.MustCompile(`Accepted \S+ for (\S+) from (\S+) port (\d+)`)
	reSudoCmd  = regexp.MustCompile(`sudo:\s+(\S+)\s*:\s+TTY=([^;]+)\s*;\s*PWD=([^;]+)\s*;\s*USER=([^;]+)\s*;\s*COMMAND=(.+)$`)
)

type AuthLogOptions struct {
	Path            string
	MaxBatchSize    int
	DedupTTL        time.Duration
	IncludeAccepted bool
}

type dedupKey struct {
	srcIP  string
	user   string
	action string
}

type logDedupEntry struct {
	lastSeen time.Time
}

type AuthLogCapturer struct {
	agentID string
	opts    AuthLogOptions
	hostIP  string

	offset    int64
	lastInode uint64
	cache     map[dedupKey]logDedupEntry
}

func NewAuthLogCapturer(agentID string, opts AuthLogOptions) *AuthLogCapturer {
	if opts.Path == "" {
		opts.Path = "/var/log/auth.log"
	}
	if opts.MaxBatchSize <= 0 {
		opts.MaxBatchSize = 200
	}
	if opts.DedupTTL <= 0 {
		opts.DedupTTL = 30 * time.Second
	}

	return &AuthLogCapturer{
		agentID: agentID,
		opts:    opts,
		hostIP:  detectPrimaryIP(),
		cache:   make(map[dedupKey]logDedupEntry, 2048),
	}
}

func ValidateAuthLogReadable(path string) error {
	p := strings.TrimSpace(path)
	if p == "" {
		p = "/var/log/auth.log"
	}

	f, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("authlog %s unreadable: %w", p, err)
	}
	_ = f.Close()
	return nil
}

func (c *AuthLogCapturer) Capture(now time.Time) ([]model.NetEvent, error) {
	f, err := os.Open(c.opts.Path)
	if err != nil {
		return nil, fmt.Errorf("open authlog %s: %w", c.opts.Path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat authlog: %w", err)
	}

	inode := inodeOf(fi)
	if c.lastInode != 0 && inode != c.lastInode {
		// log rotated
		c.offset = 0
	}
	c.lastInode = inode

	if c.offset > 0 {
		if _, err := f.Seek(c.offset, io.SeekStart); err != nil {
			c.offset = 0
			_, _ = f.Seek(0, io.SeekStart)
		}
	}

	reader := bufio.NewReader(f)

	var out []model.NetEvent
	out = make([]model.NetEvent, 0, c.opts.MaxBatchSize)

	for len(out) < c.opts.MaxBatchSize {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return out, fmt.Errorf("read authlog: %w", err)
		}

		c.offset += int64(len(line))

		ev, key, ok := c.parseLine(now, line)
		if !ok {
			continue
		}

		if c.isDeduped(now, key) {
			continue
		}

		out = append(out, ev)
	}

	c.pruneDedup(now)

	return out, nil
}

func (c *AuthLogCapturer) parseLine(now time.Time, line string) (model.NetEvent, dedupKey, bool) {
	msg := strings.TrimSpace(line)
	if msg == "" {
		return model.NetEvent{}, dedupKey{}, false
	}

	if mm := reSudoCmd.FindStringSubmatch(msg); len(mm) == 6 {
		user := strings.TrimSpace(mm[1])
		tty := strings.TrimSpace(mm[2])
		pwd := strings.TrimSpace(mm[3])
		targetUser := strings.TrimSpace(mm[4])
		command := strings.TrimSpace(mm[5])

		ev := model.NetEvent{
			AgentID:   c.agentID,
			EventType: "sudo_cmd",
			Timestamp: now.UTC(),
			SrcIP:     c.hostIP,
			DstIP:     c.hostIP,
			DstPort:   0,
			Proto:     "sudo",
			Bytes:     0,
			Extra: map[string]interface{}{
				"event_id":    uuid.NewString(),
				"source":      "auth.log",
				"action":      "sudo",
				"username":    user,
				"target_user": targetUser,
				"tty":         tty,
				"pwd":         pwd,
				"command":     command,
				"raw_message": msg,
			},
		}

		// Never dedupe sudo (commands are unique evidence)
		return ev, dedupKey{}, true
	}

	if mm := reFailed.FindStringSubmatch(msg); len(mm) == 5 {
		user := mm[2]
		ip := normalizeIP(mm[3])
		port := mm[4]

		ev := c.newSSHEndpointEvent(now, ip, 22, map[string]interface{}{
			"ssh_pid":     0,
			"action":      "failed_password",
			"username":    user,
			"src_port":    toInt(port),
			"raw_message": msg,
		})

		return ev, dedupKey{srcIP: ip, user: user, action: "failed_password"}, true
	}

	if mm := reInvalid.FindStringSubmatch(msg); len(mm) == 4 {
		user := mm[1]
		ip := normalizeIP(mm[2])
		port := mm[3]

		ev := c.newSSHEndpointEvent(now, ip, 22, map[string]interface{}{
			"ssh_pid":     0,
			"action":      "invalid_user",
			"username":    user,
			"src_port":    toInt(port),
			"raw_message": msg,
		})

		return ev, dedupKey{srcIP: ip, user: user, action: "invalid_user"}, true
	}

	if c.opts.IncludeAccepted {
		if mm := reAccepted.FindStringSubmatch(msg); len(mm) == 4 {
			user := mm[1]
			ip := normalizeIP(mm[2])
			port := mm[3]

			ev := c.newSSHEndpointEvent(now, ip, 22, map[string]interface{}{
				"ssh_pid":     0,
				"action":      "accepted",
				"username":    user,
				"src_port":    toInt(port),
				"raw_message": msg,
			})

			return ev, dedupKey{srcIP: ip, user: user, action: "accepted"}, true
		}
	}

	return model.NetEvent{}, dedupKey{}, false
}

func (c *AuthLogCapturer) isDeduped(now time.Time, key dedupKey) bool {
	if key.srcIP == "" {
		return false
	}
	if ent, ok := c.cache[key]; ok {
		if now.Sub(ent.lastSeen) <= c.opts.DedupTTL {
			ent.lastSeen = now
			c.cache[key] = ent
			return true
		}
	}

	c.cache[key] = logDedupEntry{lastSeen: now}
	return false
}

func (c *AuthLogCapturer) pruneDedup(now time.Time) {
	if len(c.cache) == 0 {
		return
	}
	for k, v := range c.cache {
		if now.Sub(v.lastSeen) > 2*c.opts.DedupTTL {
			delete(c.cache, k)
		}
	}
}

func (c *AuthLogCapturer) newSSHEndpointEvent(now time.Time, srcIP string, dstPort int, extra map[string]interface{}) model.NetEvent {
	if extra == nil {
		extra = map[string]interface{}{}
	}
	extra["event_id"] = uuid.NewString()
	extra["source"] = "auth.log"

	return model.NetEvent{
		AgentID:   c.agentID,
		EventType: "ssh_auth",
		Timestamp: now.UTC(),
		SrcIP:     srcIP,
		DstIP:     c.hostIP,
		DstPort:   dstPort,
		Proto:     "ssh",
		Bytes:     0,
		Extra:     extra,
	}
}

func inodeOf(fi os.FileInfo) uint64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0
	}
	return uint64(st.Ino)
}

func detectPrimaryIP() string {
	// Best-effort: choose the primary non-loopback IPv4 address of the host.
	// This is used as dst_ip for ssh_auth events parsed from auth.log, since the log line
	// contains the remote source IP but not the local destination IP.
	if c, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
			ip := ua.IP
			_ = c.Close()
			if ip != nil {
				if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
					return ip4.String()
				}
			}
		} else {
			_ = c.Close()
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if ip4.IsLoopback() {
				continue
			}
			return ip4.String()
		}
	}
	return ""
}

func normalizeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	return ip.String()
}

func toInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
