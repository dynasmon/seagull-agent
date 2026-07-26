package procexec

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
)

const (
	defaultProcRoot      = "/proc"
	defaultStartTimeHz   = 100.0
	defaultCmdlineMax    = 2048
	defaultMaxBatch      = 200
	defaultHashMaxBytes  = 25 * 1024 * 1024
	defaultHashCacheSize = 4096
)

var (
	reRemoteFetchExec = regexp.MustCompile(`(?i)\b(curl|wget)\b.{0,220}\|\s*\b(sh|bash|python|python3|perl)\b`)
	reReverseShell    = regexp.MustCompile(`(?i)(/dev/tcp/|nc\s+.*-e\s+|ncat\s+.*--exec|python(3)?\s+-c\s+.*socket|socat\s+.*tcp)`)
)

type Options struct {
	ProcRoot string

	MinInterval      time.Duration
	EmitInitialState bool
	MaxBatchSize     int

	CmdlineMaxBytes int

	IgnoreExeNames    map[string]bool
	IgnoreCmdContains []string

	HashExecutables   bool
	HashMaxBytes      int64
	HashCacheTTL      time.Duration
	HashCacheMaxItems int

	UsernameCacheTTL time.Duration
}

type hashEntry struct {
	sha256     string
	size       int64
	modUnix    int64
	computedAt time.Time
}

type userEntry struct {
	name      string
	expiresAt time.Time
}

type procStat struct {
	PID        int
	Comm       string
	State      string
	PPID       int
	Session    int
	TTYNr      int
	StartTicks uint64
}

type procInfo struct {
	stat procStat

	exePath string
	exeName string
	cwd     string
	cmdline string

	uid  uint32
	euid uint32
	gid  uint32
	egid uint32

	username string

	parentExePath string
	parentExeName string
}

type Capturer struct {
	agentID string
	opts    Options

	seen map[int]uint64

	hashCache map[string]hashEntry
	userCache map[uint32]userEntry

	bootTime time.Time
	lastRun  time.Time

	initialized bool
}

func New(agentID string, opts Options) *Capturer {
	applyDefaults(&opts)
	return &Capturer{
		agentID:   strings.TrimSpace(agentID),
		opts:      opts,
		seen:      make(map[int]uint64, 4096),
		hashCache: make(map[string]hashEntry, 1024),
		userCache: make(map[uint32]userEntry, 512),
	}
}

func applyDefaults(o *Options) {
	if strings.TrimSpace(o.ProcRoot) == "" {
		o.ProcRoot = defaultProcRoot
	}
	if o.MaxBatchSize <= 0 {
		o.MaxBatchSize = defaultMaxBatch
	}
	if o.CmdlineMaxBytes <= 0 {
		o.CmdlineMaxBytes = defaultCmdlineMax
	}
	if o.HashMaxBytes <= 0 {
		o.HashMaxBytes = defaultHashMaxBytes
	}
	if o.HashCacheTTL <= 0 {
		o.HashCacheTTL = 6 * time.Hour
	}
	if o.HashCacheMaxItems <= 0 {
		o.HashCacheMaxItems = defaultHashCacheSize
	}
	if o.UsernameCacheTTL <= 0 {
		o.UsernameCacheTTL = 10 * time.Minute
	}
	if o.IgnoreExeNames == nil {
		o.IgnoreExeNames = map[string]bool{}
	}
	if o.IgnoreCmdContains == nil {
		o.IgnoreCmdContains = []string{}
	}
}

func (c *Capturer) Capture(now time.Time) ([]model.NetEvent, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()

	if c.opts.MinInterval > 0 && !c.lastRun.IsZero() && now.Sub(c.lastRun) < c.opts.MinInterval {
		return nil, nil
	}
	c.lastRun = now

	if c.bootTime.IsZero() {
		c.bootTime = c.readBootTime(now)
	}

	pids, err := c.listPIDs()
	if err != nil {
		return nil, err
	}
	live := make(map[int]uint64, len(pids))

	out := make([]model.NetEvent, 0, min(len(pids), c.opts.MaxBatchSize))
	for _, pid := range pids {
		if len(out) >= c.opts.MaxBatchSize {
			break
		}

		info, err := c.readProcInfo(pid, now)
		if err != nil {
			continue
		}
		if info == nil || info.stat.StartTicks == 0 {
			continue
		}
		live[pid] = info.stat.StartTicks

		oldTicks, seen := c.seen[pid]
		if seen && oldTicks == info.stat.StartTicks {
			continue
		}
		if c.shouldIgnore(info) {
			c.seen[pid] = info.stat.StartTicks
			continue
		}

		// Keep first-pass noise low by default and only start emitting deltas afterwards.
		if !c.initialized && !c.opts.EmitInitialState {
			c.seen[pid] = info.stat.StartTicks
			continue
		}

		ev := c.toEvent(info, now)
		out = append(out, ev)
		c.seen[pid] = info.stat.StartTicks
	}

	c.cleanupSeen(live)
	c.cleanupCaches(now)
	c.initialized = true
	return out, nil
}

func (c *Capturer) cleanupSeen(live map[int]uint64) {
	for pid := range c.seen {
		if _, ok := live[pid]; !ok {
			delete(c.seen, pid)
		}
	}
}

func (c *Capturer) cleanupCaches(now time.Time) {
	if c.opts.HashCacheTTL > 0 {
		cut := now.Add(-c.opts.HashCacheTTL)
		for k, v := range c.hashCache {
			if v.computedAt.Before(cut) {
				delete(c.hashCache, k)
			}
		}
	}
	for uid, v := range c.userCache {
		if !v.expiresAt.IsZero() && now.After(v.expiresAt) {
			delete(c.userCache, uid)
		}
	}

	if len(c.hashCache) <= c.opts.HashCacheMaxItems {
		return
	}
	type pair struct {
		key string
		at  time.Time
	}
	pairs := make([]pair, 0, len(c.hashCache))
	for k, v := range c.hashCache {
		pairs = append(pairs, pair{key: k, at: v.computedAt})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].at.Before(pairs[j].at) })
	drop := len(c.hashCache) - c.opts.HashCacheMaxItems
	for i := 0; i < drop && i < len(pairs); i++ {
		delete(c.hashCache, pairs[i].key)
	}
}

func (c *Capturer) listPIDs() ([]int, error) {
	entries, err := os.ReadDir(c.opts.ProcRoot)
	if err != nil {
		return nil, fmt.Errorf("read proc root: %w", err)
	}
	out := make([]int, 0, len(entries))
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 {
			continue
		}
		out = append(out, pid)
	}
	sort.Ints(out)
	return out, nil
}

func parseProcStatLine(line string) (procStat, error) {
	ln := strings.TrimSpace(line)
	if ln == "" {
		return procStat{}, fmt.Errorf("empty stat line")
	}
	open := strings.IndexByte(ln, '(')
	close := strings.LastIndexByte(ln, ')')
	if open <= 0 || close <= open {
		return procStat{}, fmt.Errorf("invalid stat format")
	}

	pid, err := strconv.Atoi(strings.TrimSpace(ln[:open]))
	if err != nil || pid <= 0 {
		return procStat{}, fmt.Errorf("invalid pid")
	}

	comm := strings.TrimSpace(ln[open+1 : close])
	tail := strings.Fields(strings.TrimSpace(ln[close+1:]))
	// tail[0]=state tail[1]=ppid ... tail[3]=session tail[4]=tty_nr ... tail[19]=starttime
	if len(tail) < 20 {
		return procStat{}, fmt.Errorf("short stat tail")
	}
	ppid, err := strconv.Atoi(tail[1])
	if err != nil {
		return procStat{}, fmt.Errorf("invalid ppid")
	}
	session, err := strconv.Atoi(tail[3])
	if err != nil {
		session = 0
	}
	ttyNr, err := strconv.Atoi(tail[4])
	if err != nil {
		ttyNr = 0
	}
	startTicks, err := strconv.ParseUint(tail[19], 10, 64)
	if err != nil {
		return procStat{}, fmt.Errorf("invalid starttime")
	}

	return procStat{
		PID:        pid,
		Comm:       comm,
		State:      tail[0],
		PPID:       ppid,
		Session:    session,
		TTYNr:      ttyNr,
		StartTicks: startTicks,
	}, nil
}

func parseStatusUIDGID(content string) (uint32, uint32, uint32, uint32) {
	var uid, euid, gid, egid uint32
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "Uid:"):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				if v, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
					uid = uint32(v)
				}
				if v, err := strconv.ParseUint(parts[2], 10, 32); err == nil {
					euid = uint32(v)
				}
			}
		case strings.HasPrefix(line, "Gid:"):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				if v, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
					gid = uint32(v)
				}
				if v, err := strconv.ParseUint(parts[2], 10, 32); err == nil {
					egid = uint32(v)
				}
			}
		}
	}
	return uid, euid, gid, egid
}

func (c *Capturer) readProcInfo(pid int, now time.Time) (*procInfo, error) {
	statRaw, err := os.ReadFile(filepath.Join(c.opts.ProcRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return nil, err
	}
	st, err := parseProcStatLine(string(statRaw))
	if err != nil {
		return nil, err
	}

	info := &procInfo{stat: st}
	info.exePath = c.readlinkBestEffort(pid, "exe")
	if info.exePath != "" {
		info.exeName = filepath.Base(info.exePath)
	}
	if info.exeName == "" {
		info.exeName = st.Comm
	}
	info.cwd = c.readlinkBestEffort(pid, "cwd")
	info.cmdline = c.readCmdlineBestEffort(pid)

	if statusRaw, err := os.ReadFile(filepath.Join(c.opts.ProcRoot, strconv.Itoa(pid), "status")); err == nil {
		info.uid, info.euid, info.gid, info.egid = parseStatusUIDGID(string(statusRaw))
	}
	info.username = c.resolveUsername(info.euid, now)

	if st.PPID > 0 {
		info.parentExePath = c.readlinkBestEffort(st.PPID, "exe")
		if info.parentExePath != "" {
			info.parentExeName = filepath.Base(info.parentExePath)
		}
		if info.parentExeName == "" {
			if comm, err := os.ReadFile(filepath.Join(c.opts.ProcRoot, strconv.Itoa(st.PPID), "comm")); err == nil {
				info.parentExeName = strings.TrimSpace(string(comm))
			}
		}
	}
	return info, nil
}

func (c *Capturer) readCmdlineBestEffort(pid int) string {
	b, err := os.ReadFile(filepath.Join(c.opts.ProcRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil || len(b) == 0 {
		return ""
	}
	if len(b) > c.opts.CmdlineMaxBytes {
		b = b[:c.opts.CmdlineMaxBytes]
	}
	s := strings.ReplaceAll(string(b), "\x00", " ")
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	return s
}

func (c *Capturer) readlinkBestEffort(pid int, name string) string {
	target, err := os.Readlink(filepath.Join(c.opts.ProcRoot, strconv.Itoa(pid), name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(target)
}

func (c *Capturer) shouldIgnore(info *procInfo) bool {
	if info == nil {
		return true
	}
	exe := strings.ToLower(strings.TrimSpace(info.exeName))
	if exe != "" && c.opts.IgnoreExeNames[exe] {
		return true
	}
	cmd := strings.ToLower(strings.TrimSpace(info.cmdline))
	if cmd == "" {
		cmd = strings.ToLower(strings.TrimSpace(info.stat.Comm))
	}
	if cmd == "" {
		return false
	}
	for _, raw := range c.opts.IgnoreCmdContains {
		pat := strings.ToLower(strings.TrimSpace(raw))
		if pat == "" {
			continue
		}
		if strings.Contains(cmd, pat) {
			return true
		}
	}
	return false
}

func (c *Capturer) resolveUsername(uid uint32, now time.Time) string {
	if v, ok := c.userCache[uid]; ok && (v.expiresAt.IsZero() || now.Before(v.expiresAt)) {
		return v.name
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	name := ""
	if err == nil && u != nil {
		name = strings.TrimSpace(u.Username)
	}
	c.userCache[uid] = userEntry{
		name:      name,
		expiresAt: now.Add(c.opts.UsernameCacheTTL),
	}
	return name
}

func (c *Capturer) toEvent(info *procInfo, now time.Time) model.NetEvent {
	startAt := c.bootTime.Add(time.Duration(float64(info.stat.StartTicks)/defaultStartTimeHz) * time.Second).UTC()
	cmdline := strings.TrimSpace(info.cmdline)
	if cmdline == "" {
		cmdline = strings.TrimSpace(info.stat.Comm)
	}

	extra := map[string]interface{}{
		"collector":           "proc_exec",
		"collection_method":   "procfs_poll",
		"signal_family":       "execution",
		"pid":                 info.stat.PID,
		"ppid":                info.stat.PPID,
		"session_id":          info.stat.Session,
		"tty_nr":              info.stat.TTYNr,
		"process_start_time":  startAt.Format(time.RFC3339Nano),
		"process_start_ticks": info.stat.StartTicks,
		"process_state":       info.stat.State,
		"exe_path":            info.exePath,
		"exe_name":            info.exeName,
		"comm":                info.stat.Comm,
		"binary":              info.exeName,
		"cmdline":             cmdline,
		"argv":                cmdline,
		"cwd":                 info.cwd,
		"uid":                 int(info.uid),
		"euid":                int(info.euid),
		"gid":                 int(info.gid),
		"egid":                int(info.egid),
		"username":            info.username,
		"parent_exe_path":     info.parentExePath,
		"parent_exe_name":     info.parentExeName,
	}

	patterns := classifyExecutionPatterns(info, cmdline)
	if len(patterns) > 0 {
		extra["exec_patterns"] = patterns
		extra["exec_pattern"] = patterns[0]
	}

	if c.opts.HashExecutables && info.exePath != "" {
		if sha, ok := c.hashExecutable(info.exePath, now); ok {
			extra["exe_sha256"] = sha
		}
	}

	return model.NetEvent{
		AgentID:   c.agentID,
		EventType: "proc_exec",
		Timestamp: now,
		Proto:     "proc",
		Bytes:     0,
		Extra:     extra,
	}
}

func classifyExecutionPatterns(info *procInfo, cmdline string) []string {
	lcmd := strings.ToLower(strings.TrimSpace(cmdline))
	exe := strings.ToLower(strings.TrimSpace(info.exeName))
	parent := strings.ToLower(strings.TrimSpace(info.parentExeName))
	out := make([]string, 0, 4)

	if lcmd != "" && reRemoteFetchExec.MatchString(lcmd) {
		out = append(out, "remote_fetch_exec")
	}
	if lcmd != "" && reReverseShell.MatchString(lcmd) {
		out = append(out, "reverse_shell")
	}
	if isShell(exe) {
		out = append(out, "shell_spawn")
	}
	if isInterpreter(exe) {
		out = append(out, "interpreter")
	}
	if isLOLBin(exe) {
		out = append(out, "lolbin")
	}
	if isNetworkService(parent) && isShell(exe) {
		out = append(out, "service_shell_child")
	}
	return dedupStrings(out)
}

func dedupStrings(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, it := range items {
		v := strings.TrimSpace(strings.ToLower(it))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func isShell(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sh", "bash", "dash", "zsh", "ksh", "fish":
		return true
	default:
		return false
	}
}

func isInterpreter(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "python", "python3", "perl", "php", "ruby", "node":
		return true
	default:
		return false
	}
}

func isLOLBin(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "bash", "sh", "python", "python3", "perl", "php", "ruby", "node", "nc", "ncat", "socat", "curl", "wget", "openssl", "base64":
		return true
	default:
		return false
	}
}

func isNetworkService(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "nginx", "apache2", "httpd", "caddy", "traefik", "php-fpm", "gunicorn", "uwsgi":
		return true
	default:
		return false
	}
}

func (c *Capturer) hashExecutable(path string, now time.Time) (string, bool) {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return "", false
	}
	if st.Size() < 0 || st.Size() > c.opts.HashMaxBytes {
		return "", false
	}
	key := strings.TrimSpace(path)
	modUnix := st.ModTime().UnixNano()

	if cached, ok := c.hashCache[key]; ok {
		if cached.size == st.Size() && cached.modUnix == modUnix && now.Sub(cached.computedAt) <= c.opts.HashCacheTTL {
			return cached.sha256, cached.sha256 != ""
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, c.opts.HashMaxBytes+1)); err != nil {
		return "", false
	}
	sum := hex.EncodeToString(h.Sum(nil))
	c.hashCache[key] = hashEntry{
		sha256:     sum,
		size:       st.Size(),
		modUnix:    modUnix,
		computedAt: now,
	}
	return sum, true
}

func (c *Capturer) readBootTime(now time.Time) time.Time {
	statPath := filepath.Join(c.opts.ProcRoot, "stat")
	f, err := os.Open(statPath)
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(line, "btime ") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) != 2 {
				break
			}
			sec, e := strconv.ParseInt(parts[1], 10, 64)
			if e != nil || sec <= 0 {
				break
			}
			return time.Unix(sec, 0).UTC()
		}
	}

	// Fallback with uptime approximation.
	upRaw, err := os.ReadFile(filepath.Join(c.opts.ProcRoot, "uptime"))
	if err != nil {
		return now
	}
	parts := strings.Fields(string(upRaw))
	if len(parts) < 1 {
		return now
	}
	sec, err := strconv.ParseFloat(parts[0], 64)
	if err != nil || sec <= 0 {
		return now
	}
	return now.Add(-time.Duration(sec * float64(time.Second))).UTC()
}
