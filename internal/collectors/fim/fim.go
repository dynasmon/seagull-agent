package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
)

const (
	defaultMaxBatch       = 200
	defaultHashMaxBytes   = 2 * 1024 * 1024
	defaultMinInterval    = 30 * time.Second
	defaultHashCacheItems = 4096
)

type Options struct {
	WatchPaths []string
	Exclude    []string

	MinInterval      time.Duration
	MaxBatchSize     int
	MaxDepth         int
	EmitInitialState bool

	HashEnabled       bool
	HashMaxBytes      int64
	HashCacheTTL      time.Duration
	HashCacheMaxItems int
}

type fileState struct {
	Path     string
	Category string
	Exists   bool

	Size    int64
	ModUnix int64
	Mode    uint32
	UID     uint32
	GID     uint32
	Inode   uint64
	IsDir   bool

	Digest string
}

type hashEntry struct {
	value      string
	size       int64
	modUnix    int64
	computedAt time.Time
}

type Capturer struct {
	agentID string
	opts    Options

	lastRun time.Time

	initialized bool
	snapshot    map[string]fileState
	inodeIndex  map[uint64]string

	hashCache map[string]hashEntry
}

func New(agentID string, opts Options) *Capturer {
	applyDefaults(&opts)
	return &Capturer{
		agentID:   strings.TrimSpace(agentID),
		opts:      opts,
		snapshot:  make(map[string]fileState, 2048),
		inodeIndex: make(map[uint64]string, 2048),
		hashCache: make(map[string]hashEntry, 1024),
	}
}

func applyDefaults(o *Options) {
	if len(o.WatchPaths) == 0 {
		o.WatchPaths = defaultWatchPaths()
	}
	if o.MaxBatchSize <= 0 {
		o.MaxBatchSize = defaultMaxBatch
	}
	if o.MinInterval <= 0 {
		o.MinInterval = defaultMinInterval
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 4
	}
	if o.HashMaxBytes <= 0 {
		o.HashMaxBytes = defaultHashMaxBytes
	}
	if o.HashCacheTTL <= 0 {
		o.HashCacheTTL = 6 * time.Hour
	}
	if o.HashCacheMaxItems <= 0 {
		o.HashCacheMaxItems = defaultHashCacheItems
	}
}

func defaultWatchPaths() []string {
	return []string{
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron",
		"/var/spool/cron/crontabs",
		"/root/.ssh/authorized_keys",
		"/home/*/.ssh/authorized_keys",
		"/etc/ssh/sshd_config",
		"/etc/ssh/ssh_config",
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/zsh/zshrc",
		"/etc/rc.local",
		"/etc/passwd",
		"/etc/shadow",
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

	curr, inodeIndex := c.scan(now)
	if !c.initialized {
		c.snapshot = curr
		c.inodeIndex = inodeIndex
		c.initialized = true
		if !c.opts.EmitInitialState {
			return nil, nil
		}
	}

	events := c.diff(now, c.snapshot, curr, c.inodeIndex)
	if len(events) > c.opts.MaxBatchSize {
		events = events[:c.opts.MaxBatchSize]
	}

	c.snapshot = curr
	c.inodeIndex = inodeIndex
	c.cleanupHashCache(now)
	return events, nil
}

func (c *Capturer) scan(now time.Time) (map[string]fileState, map[uint64]string) {
	out := make(map[string]fileState, 2048)
	inodeIdx := make(map[uint64]string, 2048)
	for _, raw := range c.opts.WatchPaths {
		expanded := expandWatchPath(raw)
		for _, p := range expanded {
			c.scanPath(now, p, out, inodeIdx)
		}
	}
	return out, inodeIdx
}

func expandWatchPath(path string) []string {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil
	}
	if strings.Contains(p, "*") {
		matches, err := filepath.Glob(p)
		if err != nil || len(matches) == 0 {
			return nil
		}
		return matches
	}
	return []string{p}
}

func (c *Capturer) scanPath(now time.Time, path string, out map[string]fileState, inodeIdx map[uint64]string) {
	path = strings.TrimSpace(path)
	if path == "" || c.isExcluded(path) {
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if info.IsDir() {
		c.walkDir(now, path, out, inodeIdx)
		return
	}
	st := c.buildState(now, path, info)
	out[path] = st
	if st.Inode > 0 {
		inodeIdx[st.Inode] = path
	}
}

func (c *Capturer) walkDir(now time.Time, root string, out map[string]fileState, inodeIdx map[uint64]string) {
	baseDepth := pathDepth(root)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if path != root && c.isExcluded(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if c.opts.MaxDepth > 0 && pathDepth(path)-baseDepth > c.opts.MaxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return nil
		}
		st := c.buildState(now, path, info)
		out[path] = st
		if st.Inode > 0 {
			inodeIdx[st.Inode] = path
		}
		return nil
	})
}

func pathDepth(path string) int {
	p := filepath.Clean(path)
	if p == "/" {
		return 1
	}
	return len(strings.Split(p, string(filepath.Separator)))
}

func (c *Capturer) buildState(now time.Time, path string, info fs.FileInfo) fileState {
	st := fileState{
		Path:     path,
		Category: classifyPathCategory(path),
		Exists:   true,
		Size:     info.Size(),
		ModUnix:  info.ModTime().UnixNano(),
		Mode:     uint32(info.Mode().Perm()),
		IsDir:    info.IsDir(),
	}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok {
		st.UID = sys.Uid
		st.GID = sys.Gid
		st.Inode = sys.Ino
	}
	if c.opts.HashEnabled && !st.IsDir && st.Size >= 0 && st.Size <= c.opts.HashMaxBytes {
		if dig, ok := c.hashFile(path, info, now); ok {
			st.Digest = dig
		}
	}
	return st
}

func (c *Capturer) hashFile(path string, info fs.FileInfo, now time.Time) (string, bool) {
	key := filepath.Clean(path)
	mod := info.ModTime().UnixNano()
	if cached, ok := c.hashCache[key]; ok {
		if cached.size == info.Size() && cached.modUnix == mod && now.Sub(cached.computedAt) <= c.opts.HashCacheTTL {
			return cached.value, cached.value != ""
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
		value:      sum,
		size:       info.Size(),
		modUnix:    mod,
		computedAt: now,
	}
	return sum, true
}

func (c *Capturer) cleanupHashCache(now time.Time) {
	if c.opts.HashCacheTTL > 0 {
		cut := now.Add(-c.opts.HashCacheTTL)
		for k, v := range c.hashCache {
			if v.computedAt.Before(cut) {
				delete(c.hashCache, k)
			}
		}
	}
	if len(c.hashCache) <= c.opts.HashCacheMaxItems {
		return
	}
	type pair struct {
		key string
		at  time.Time
	}
	items := make([]pair, 0, len(c.hashCache))
	for k, v := range c.hashCache {
		items = append(items, pair{key: k, at: v.computedAt})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].at.Before(items[j].at) })
	drop := len(c.hashCache) - c.opts.HashCacheMaxItems
	for i := 0; i < drop && i < len(items); i++ {
		delete(c.hashCache, items[i].key)
	}
}

func (c *Capturer) diff(now time.Time, prev, curr map[string]fileState, prevInode map[uint64]string) []model.NetEvent {
	out := make([]model.NetEvent, 0, 64)
	renamedFrom := make(map[string]struct{}, 16)

	for path, cur := range curr {
		old, ok := prev[path]
		if !ok {
			if cur.Inode > 0 {
				if oldPath, exists := prevInode[cur.Inode]; exists && oldPath != path {
					renamedFrom[oldPath] = struct{}{}
					oldSt := fileState{Path: oldPath, Category: cur.Category}
					if prevState, okPrev := prev[oldPath]; okPrev {
						oldSt = prevState
					}
					out = append(out, c.makeEvent(now, cur, "rename", &oldSt))
					continue
				}
			}
			out = append(out, c.makeEvent(now, cur, "create", nil))
			continue
		}

		action := classifyChangeAction(old, cur)
		if action == "" {
			continue
		}
		oldCopy := old
		out = append(out, c.makeEvent(now, cur, action, &oldCopy))
	}

	for path, old := range prev {
		if _, ok := curr[path]; ok {
			continue
		}
		if _, renamed := renamedFrom[path]; renamed {
			continue
		}
		oldCopy := old
		out = append(out, c.makeDeleteEvent(now, oldCopy))
	}

	return out
}

func classifyChangeAction(old, cur fileState) string {
	if old.Digest != "" && cur.Digest != "" && old.Digest != cur.Digest {
		return "modify"
	}
	if old.Size != cur.Size || old.ModUnix != cur.ModUnix {
		return "modify"
	}
	if old.UID != cur.UID || old.GID != cur.GID {
		return "ownership_change"
	}
	if old.Mode != cur.Mode {
		return "permission_change"
	}
	return ""
}

func (c *Capturer) makeDeleteEvent(now time.Time, old fileState) model.NetEvent {
	extra := c.baseExtra(old, "delete")
	extra["previous"] = map[string]interface{}{
		"path":   old.Path,
		"uid":    old.UID,
		"gid":    old.GID,
		"mode":   fmt.Sprintf("%#o", old.Mode),
		"size":   old.Size,
		"digest": old.Digest,
	}
	return model.NetEvent{
		AgentID:   c.agentID,
		EventType: eventTypeForCategory(old.Category),
		Timestamp: now,
		Proto:     "file",
		Bytes:     0,
		Extra:     extra,
	}
}

func (c *Capturer) makeEvent(now time.Time, cur fileState, action string, old *fileState) model.NetEvent {
	extra := c.baseExtra(cur, action)
	extra["uid"] = cur.UID
	extra["gid"] = cur.GID
	extra["mode"] = fmt.Sprintf("%#o", cur.Mode)
	extra["size"] = cur.Size
	if cur.Digest != "" {
		extra["digest_after"] = cur.Digest
	}

	if old != nil {
		extra["previous"] = map[string]interface{}{
			"path":   old.Path,
			"uid":    old.UID,
			"gid":    old.GID,
			"mode":   fmt.Sprintf("%#o", old.Mode),
			"size":   old.Size,
			"digest": old.Digest,
		}
		if old.Digest != "" {
			extra["digest_before"] = old.Digest
		}
	}
	if action == "rename" && old != nil && old.Path != "" {
		extra["path_from"] = old.Path
		extra["path_to"] = cur.Path
	}

	return model.NetEvent{
		AgentID:   c.agentID,
		EventType: eventTypeForCategory(cur.Category),
		Timestamp: now,
		Proto:     "file",
		Bytes:     int(max64(cur.Size, 0)),
		Extra:     extra,
	}
}

func (c *Capturer) baseExtra(st fileState, action string) map[string]interface{} {
	category := st.Category
	persist, tamper := classifyRiskFlags(category)
	return map[string]interface{}{
		"collector":            "fim_poll",
		"collection_method":    "poll_snapshot",
		"signal_family":        "file_integrity",
		"path":                 st.Path,
		"path_category":        category,
		"action":               action,
		"persistence_related":  persist,
		"tamper_related":       tamper,
		"inode":                st.Inode,
		"is_dir":               st.IsDir,
		"modified_unix_nano":   st.ModUnix,
		"watch_model_revision": 1,
	}
}

func classifyPathCategory(path string) string {
	p := strings.ToLower(filepath.Clean(path))
	switch {
	case strings.Contains(p, "/systemd/") && strings.HasSuffix(p, ".service"):
		return "systemd_unit"
	case strings.Contains(p, "/systemd/"):
		return "systemd_override"
	case strings.Contains(p, "/cron"):
		return "cron"
	case strings.HasSuffix(p, "/authorized_keys"):
		return "ssh_authorized_keys"
	case strings.Contains(p, "/etc/ssh/"):
		return "ssh_config"
	case p == "/etc/profile" || strings.Contains(p, "bashrc") || strings.Contains(p, "zshrc"):
		return "shell_profile"
	case p == "/etc/rc.local":
		return "rc_local"
	case p == "/etc/passwd" || p == "/etc/shadow":
		return "security_file"
	default:
		return "persistence_path"
	}
}

func classifyRiskFlags(category string) (bool, bool) {
	switch category {
	case "systemd_unit", "systemd_override", "cron", "ssh_authorized_keys", "shell_profile", "rc_local", "persistence_path":
		return true, false
	case "security_file", "ssh_config":
		return false, true
	default:
		return false, false
	}
}

func eventTypeForCategory(category string) string {
	switch category {
	case "systemd_unit", "systemd_override":
		return "persistence_systemd"
	case "cron":
		return "persistence_cron"
	case "ssh_authorized_keys":
		return "ssh_key_change"
	default:
		return "fim_change"
	}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (c *Capturer) isExcluded(path string) bool {
	p := filepath.Clean(strings.TrimSpace(path))
	if p == "" {
		return true
	}
	for _, ex := range c.opts.Exclude {
		e := filepath.Clean(strings.TrimSpace(ex))
		if e == "" {
			continue
		}
		if p == e || strings.HasPrefix(p, e+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
