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
		cache:   make(map[dedupKey]logDedupEntry, 2048),
	}
}

func (c *AuthLogCapturer) Capture(now time.Time) ([]model.NetEvent, error) {
	f, err := os.Open(c.opts.Path)
	if err != nil {
		return nil, fmt.Errorf("open authlog %s: %w", c.opts.Path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat authlog %s: %w", c.opts.Path, err)
	}

	inode := inodeOf(fi)
	if c.lastInode != 0 && inode != 0 && inode != c.lastInode {
		c.offset = 0
	}
	c.lastInode = inode

	if fi.Size() < c.offset {
		c.offset = 0
	}

	if _, err := f.Seek(c.offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek authlog: %w", err)
	}

	out := make([]model.NetEvent, 0, 64)

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 256*1024)

	for scanner.Scan() {
		ev, key, ok := c.parseLine(now, scanner.Text())
		if !ok {
			continue
		}
		if c.isDuplicate(now, key) {
			continue
		}

		out = append(out, ev)
		if len(out) >= c.opts.MaxBatchSize {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("scan authlog: %w", err)
	}

	if pos, err := f.Seek(0, io.SeekCurrent); err == nil {
		c.offset = pos
	}

	c.cleanup(now)
	return out, nil
}

func (c *AuthLogCapturer) isDuplicate(now time.Time, key dedupKey) bool {
	if key.srcIP == "" || key.action == "" {
		return false
	}

	if e, ok := c.cache[key]; ok && now.Sub(e.lastSeen) < c.opts.DedupTTL {
		return true
	}

	c.cache[key] = logDedupEntry{lastSeen: now}
	return false
}

func (c *AuthLogCapturer) cleanup(now time.Time) {
	cut := now.Add(-2 * c.opts.DedupTTL)
	for k, v := range c.cache {
		if v.lastSeen.Before(cut) {
			delete(c.cache, k)
		}
	}
}

var (
	reSSHD       = regexp.MustCompile(`\bsshd\[(\d+)\]:\s+(.*)$`)
	reFailedPwd  = regexp.MustCompile(`^Failed password for (invalid user )?(\S+) from (\S+) port (\d+)`)
	reInvalid    = regexp.MustCompile(`^Invalid user (\S+) from (\S+) port (\d+)`)
	reAccepted   = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	reMaxAuth    = regexp.MustCompile(`^error: maximum authentication attempts exceeded for (\S+) from (\S+) port (\d+)`)
	reClosed     = regexp.MustCompile(`^Connection closed by (?:authenticating user )?(\S+)?\s*(\S+)\s+port\s+(\d+)`)
	reDisconnect = regexp.MustCompile(`^Disconnected from (invalid user )?(\S+)\s+(\S+)\s+port\s+(\d+)`)
)

func (c *AuthLogCapturer) parseLine(now time.Time, line string) (model.NetEvent, dedupKey, bool) {
	m := reSSHD.FindStringSubmatch(line)
	if len(m) != 3 {
		return model.NetEvent{}, dedupKey{}, false
	}

	pid := m[1]
	msg := m[2]

	if mm := reFailedPwd.FindStringSubmatch(msg); len(mm) == 5 {
		user := mm[2]
		ip := normalizeIP(mm[3])
		port := mm[4]

		ev := c.newSSHEndpointEvent(now, ip, 22, map[string]interface{}{
			"ssh_pid":     pid,
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
			"ssh_pid":     pid,
			"action":      "invalid_user",
			"username":    user,
			"src_port":    toInt(port),
			"raw_message": msg,
		})

		return ev, dedupKey{srcIP: ip, user: user, action: "invalid_user"}, true
	}

	if mm := reMaxAuth.FindStringSubmatch(msg); len(mm) == 4 {
		user := mm[1]
		ip := normalizeIP(mm[2])
		port := mm[3]

		ev := c.newSSHEndpointEvent(now, ip, 22, map[string]interface{}{
			"ssh_pid":     pid,
			"action":      "max_auth_attempts",
			"username":    user,
			"src_port":    toInt(port),
			"raw_message": msg,
		})

		return ev, dedupKey{srcIP: ip, user: user, action: "max_auth_attempts"}, true
	}

	if c.opts.IncludeAccepted {
		if mm := reAccepted.FindStringSubmatch(msg); len(mm) == 5 {
			method := mm[1]
			user := mm[2]
			ip := normalizeIP(mm[3])
			port := mm[4]

			ev := c.newSSHEndpointEvent(now, ip, 22, map[string]interface{}{
				"ssh_pid":     pid,
				"action":      "accepted",
				"auth_method": method,
				"username":    user,
				"src_port":    toInt(port),
				"raw_message": msg,
			})

			return ev, dedupKey{srcIP: ip, user: user, action: "accepted_" + method}, true
		}
	}

	if reClosed.MatchString(msg) || reDisconnect.MatchString(msg) {
		return model.NetEvent{}, dedupKey{}, false
	}

	return model.NetEvent{}, dedupKey{}, false
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
