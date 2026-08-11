package ssh

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
	"github.com/dynasmon/seagull-agent/internal/netcontext"
	"github.com/dynasmon/seagull-agent/protocol"
)

var (
	reFailed   = regexp.MustCompile(`Failed password for (invalid user )?(\S+) from (\S+) port (\d+)`)
	reInvalid  = regexp.MustCompile(`Invalid user (\S+) from (\S+) port (\d+)`)
	reAccepted = regexp.MustCompile(`Accepted \S+ for (\S+) from (\S+) port (\d+)`)
	reSudoCmd  = regexp.MustCompile(`sudo:\s+(\S+)\s*:\s+TTY=([^;]+)\s*;\s*PWD=([^;]+)\s*;\s*USER=([^;]+)\s*;\s*COMMAND=(.+)$`)
)

type AuthLogOptions struct {
	Path            string
	CheckpointPath  string
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

type authLogCheckpoint struct {
	Version int    `json:"version"`
	AgentID string `json:"agent_id"`
	Path    string `json:"path"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	Offset  int64  `json:"offset"`
}

type authLogCaptureState struct {
	offset     int64
	lastDevice uint64
	lastInode  uint64
	cache      map[dedupKey]logDedupEntry
}

type AuthLogCapturer struct {
	agentID string
	opts    AuthLogOptions
	hostIP  string

	offset     int64
	lastDevice uint64
	lastInode  uint64
	cache      map[dedupKey]logDedupEntry
	pending    *authLogCaptureState
	loadErr    error
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

	capturer := &AuthLogCapturer{
		agentID: agentID,
		opts:    opts,
		hostIP:  detectPrimaryIP(),
		cache:   make(map[dedupKey]logDedupEntry, 2048),
	}
	capturer.loadErr = capturer.loadCheckpoint()
	return capturer
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

func ResolveAuthLogPath(configuredPath string) (string, error) {
	candidates := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		candidates = append(candidates, p)
	}

	add(configuredPath)
	add("/var/log/auth.log")
	add("/var/log/secure")
	add("/host/var/log/auth.log")
	add("/host/var/log/secure")

	lastErr := error(nil)
	for _, p := range candidates {
		if err := ValidateAuthLogReadable(p); err == nil {
			return p, nil
		} else {
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no authlog candidates configured")
	}
	return "", lastErr
}

func (c *AuthLogCapturer) Capture(now time.Time) ([]protocol.NetEvent, error) {
	if c.loadErr != nil {
		return nil, c.loadErr
	}
	if c.pending != nil {
		c.rollback()
	}
	f, err := os.Open(c.opts.Path)
	if err != nil {
		return nil, fmt.Errorf("open authlog %s: %w", c.opts.Path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat authlog: %w", err)
	}

	c.pending = &authLogCaptureState{
		offset:     c.offset,
		lastDevice: c.lastDevice,
		lastInode:  c.lastInode,
		cache:      cloneDedupCache(c.cache),
	}
	device, inode := fileIdentity(fi)
	if c.lastInode != 0 && (inode != c.lastInode || device != c.lastDevice) {
		c.offset = 0
	}
	if c.offset > fi.Size() {
		c.offset = 0
	}
	c.lastDevice = device
	c.lastInode = inode

	if c.offset > 0 {
		if _, err := f.Seek(c.offset, io.SeekStart); err != nil {
			c.offset = 0
			_, _ = f.Seek(0, io.SeekStart)
		}
	}

	reader := bufio.NewReader(f)

	var out []protocol.NetEvent
	out = make([]protocol.NetEvent, 0, c.opts.MaxBatchSize)

	for len(out) < c.opts.MaxBatchSize {
		lineOffset := c.offset
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			c.rollback()
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

		eventID := c.eventID(lineOffset, line)
		ev.EventID = eventID
		if ev.Extra == nil {
			ev.Extra = map[string]interface{}{}
		}
		ev.Extra["event_id"] = eventID
		out = append(out, ev)
	}

	c.pruneDedup(now)

	return out, nil
}

func (c *AuthLogCapturer) Commit() error {
	if c == nil || c.pending == nil {
		return nil
	}
	c.pending = nil
	path := strings.TrimSpace(c.opts.CheckpointPath)
	if path == "" {
		return nil
	}
	state := authLogCheckpoint{
		Version: 1,
		AgentID: strings.TrimSpace(c.agentID),
		Path:    filepath.Clean(c.opts.Path),
		Device:  c.lastDevice,
		Inode:   c.lastInode,
		Offset:  c.offset,
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal authlog checkpoint: %w", err)
	}
	if err := agentcfg.AtomicWriteFile(path, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("persist authlog checkpoint: %w", err)
	}
	return nil
}

func (c *AuthLogCapturer) Rollback() {
	if c == nil {
		return
	}
	c.rollback()
}

func (c *AuthLogCapturer) rollback() {
	if c.pending == nil {
		return
	}
	c.offset = c.pending.offset
	c.lastDevice = c.pending.lastDevice
	c.lastInode = c.pending.lastInode
	c.cache = c.pending.cache
	c.pending = nil
}

func (c *AuthLogCapturer) loadCheckpoint() error {
	path := strings.TrimSpace(c.opts.CheckpointPath)
	if path == "" {
		return nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read authlog checkpoint: %w", err)
	}
	var state authLogCheckpoint
	if err := json.Unmarshal(payload, &state); err != nil {
		return fmt.Errorf("parse authlog checkpoint: %w", err)
	}
	if state.Version != 1 {
		return fmt.Errorf("unsupported authlog checkpoint version %d", state.Version)
	}
	if strings.TrimSpace(state.AgentID) != strings.TrimSpace(c.agentID) {
		return fmt.Errorf("authlog checkpoint agent ID mismatch")
	}
	if state.Offset < 0 {
		return fmt.Errorf("authlog checkpoint offset is invalid")
	}
	if filepath.Clean(state.Path) != filepath.Clean(c.opts.Path) {
		return nil
	}
	c.lastDevice = state.Device
	c.lastInode = state.Inode
	c.offset = state.Offset
	return nil
}

func cloneDedupCache(in map[dedupKey]logDedupEntry) map[dedupKey]logDedupEntry {
	out := make(map[dedupKey]logDedupEntry, len(in))
	for key, entry := range in {
		out[key] = entry
	}
	return out
}

func (c *AuthLogCapturer) eventID(offset int64, line string) string {
	identity := fmt.Sprintf(
		"%s\x00%s\x00%d\x00%d\x00%d\x00%s",
		strings.TrimSpace(c.agentID),
		filepath.Clean(c.opts.Path),
		c.lastDevice,
		c.lastInode,
		offset,
		line,
	)
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(identity)).String()
}

func (c *AuthLogCapturer) parseLine(now time.Time, line string) (protocol.NetEvent, dedupKey, bool) {
	msg := strings.TrimSpace(line)
	if msg == "" {
		return protocol.NetEvent{}, dedupKey{}, false
	}

	if mm := reSudoCmd.FindStringSubmatch(msg); len(mm) == 6 {
		user := strings.TrimSpace(mm[1])
		tty := strings.TrimSpace(mm[2])
		pwd := strings.TrimSpace(mm[3])
		targetUser := strings.TrimSpace(mm[4])
		command := strings.TrimSpace(mm[5])

		ev := protocol.NetEvent{
			AgentID:   c.agentID,
			EventType: "sudo_cmd",
			Timestamp: now.UTC(),
			SrcIP:     c.hostIP,
			DstIP:     c.hostIP,
			DstPort:   0,
			Proto:     "sudo",
			Bytes:     0,
			Extra: map[string]interface{}{
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

	return protocol.NetEvent{}, dedupKey{}, false
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

func (c *AuthLogCapturer) newSSHEndpointEvent(now time.Time, remote string, dstPort int, extra map[string]interface{}) protocol.NetEvent {
	if extra == nil {
		extra = map[string]interface{}{}
	}
	extra["source"] = "auth.log"

	srcIP, srcHost := splitRemoteEndpoint(remote)
	if srcHost != "" {
		extra["src_host"] = srcHost
	}

	return protocol.NetEvent{
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

func fileIdentity(fi os.FileInfo) (uint64, uint64) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0
	}
	return uint64(st.Dev), uint64(st.Ino)
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

	return netcontext.PrimaryIPv4()
}

func normalizeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	return ip.String()
}

func splitRemoteEndpoint(s string) (string, string) {
	remote := strings.TrimSpace(s)
	if remote == "" {
		return "", ""
	}
	ip := net.ParseIP(remote)
	if ip == nil {
		return "", remote
	}
	return ip.String(), ""
}

func toInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
