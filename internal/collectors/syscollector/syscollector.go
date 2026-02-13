package syscollector

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

type Options struct {
	CmdTimeout     time.Duration
	MaxOutputBytes int64
	MaxPackages    int
}

type Result struct {
	Snapshot model.InventorySnapshot
	Warnings []string
}

func Collect(ctx context.Context, opts Options) (Result, error) {
	if opts.CmdTimeout <= 0 {
		opts.CmdTimeout = 10 * time.Second
	}
	if opts.MaxOutputBytes <= 0 {
		opts.MaxOutputBytes = 8 << 20 // 8 MiB
	}
	if opts.MaxPackages <= 0 {
		opts.MaxPackages = 50000
	}

	now := time.Now().UTC()
	osInfo := collectOS()

	pkgs, manager, warns, err := collectPackages(ctx, opts)
	if err != nil {
		return Result{}, err
	}

	hash := hashPackages(pkgs)

	snap := model.InventorySnapshot{
		SchemaVersion: 1,
		CollectedAt:   &now,
		OS:            osInfo,
		Packages:      pkgs,
		PackagesHash:  hash,
		PackagesCount: len(pkgs),
		Manager:       manager,
		Extra:         map[string]interface{}{},
	}

	if len(warns) > 0 {
		snap.Extra["warnings"] = warns
	}

	return Result{Snapshot: snap, Warnings: warns}, nil
}

func collectOS() map[string]interface{} {
	info := map[string]interface{}{
		"goos":   runtime.GOOS,
		"goarch": runtime.GOARCH,
	}

	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		m := parseOSRelease(string(b))
		for k, v := range m {
			info[k] = v
		}
	}

	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info["kernel_release"] = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		info["machine"] = strings.TrimSpace(string(out))
	}

	return info
}

func parseOSRelease(s string) map[string]string {
	m := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, "\"'")
		if k != "" {
			m[strings.ToLower(k)] = v
		}
	}
	return m
}

func collectPackages(ctx context.Context, opts Options) ([]model.PackageEntry, string, []string, error) {
	var warns []string

	// Prefer native manager output for accuracy.
	if path, _ := exec.LookPath("dpkg-query"); path != "" {
		pkgs, w, err := runDpkg(ctx, opts)
		return pkgs, "dpkg", append(warns, w...), err
	}
	if path, _ := exec.LookPath("rpm"); path != "" {
		pkgs, w, err := runRPM(ctx, opts)
		return pkgs, "rpm", append(warns, w...), err
	}
	if path, _ := exec.LookPath("pacman"); path != "" {
		pkgs, w, err := runPacman(ctx, opts)
		return pkgs, "pacman", append(warns, w...), err
	}
	if path, _ := exec.LookPath("apk"); path != "" {
		pkgs, w, err := runAPK(ctx, opts)
		return pkgs, "apk", append(warns, w...), err
	}

	return []model.PackageEntry{}, "unknown", []string{"no_package_manager_detected"}, nil
}

func runDpkg(ctx context.Context, opts Options) ([]model.PackageEntry, []string, error) {
	ctxCmd, cancel := context.WithTimeout(ctx, opts.CmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctxCmd, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n")
	lines, truncated, err := runLimitedLines(cmd, opts.MaxOutputBytes)
	if err != nil {
		return nil, nil, err
	}
	pkgs := make([]model.PackageEntry, 0, minInt(len(lines), opts.MaxPackages))
	for _, ln := range lines {
		parts := strings.Split(ln, "\t")
		if len(parts) < 2 {
			continue
		}
		p := model.PackageEntry{Name: parts[0], Version: parts[1]}
		if len(parts) >= 3 {
			p.Arch = parts[2]
		}
		if p.Name == "" || p.Version == "" {
			continue
		}
		pkgs = append(pkgs, p)
		if len(pkgs) >= opts.MaxPackages {
			break
		}
	}
	var warns []string
	if truncated {
		warns = append(warns, "package_list_truncated")
	}
	if len(lines) > opts.MaxPackages {
		warns = append(warns, "package_list_capped")
	}
	return pkgs, warns, nil
}

func runRPM(ctx context.Context, opts Options) ([]model.PackageEntry, []string, error) {
	ctxCmd, cancel := context.WithTimeout(ctx, opts.CmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctxCmd, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n")
	lines, truncated, err := runLimitedLines(cmd, opts.MaxOutputBytes)
	if err != nil {
		return nil, nil, err
	}
	pkgs := make([]model.PackageEntry, 0, minInt(len(lines), opts.MaxPackages))
	for _, ln := range lines {
		parts := strings.Split(ln, "\t")
		if len(parts) < 2 {
			continue
		}
		p := model.PackageEntry{Name: parts[0], Version: parts[1]}
		if len(parts) >= 3 {
			p.Arch = parts[2]
		}
		if p.Name == "" || p.Version == "" {
			continue
		}
		pkgs = append(pkgs, p)
		if len(pkgs) >= opts.MaxPackages {
			break
		}
	}
	var warns []string
	if truncated {
		warns = append(warns, "package_list_truncated")
	}
	if len(lines) > opts.MaxPackages {
		warns = append(warns, "package_list_capped")
	}
	return pkgs, warns, nil
}

func runPacman(ctx context.Context, opts Options) ([]model.PackageEntry, []string, error) {
	ctxCmd, cancel := context.WithTimeout(ctx, opts.CmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctxCmd, "pacman", "-Q")
	lines, truncated, err := runLimitedLines(cmd, opts.MaxOutputBytes)
	if err != nil {
		return nil, nil, err
	}
	pkgs := make([]model.PackageEntry, 0, minInt(len(lines), opts.MaxPackages))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		// pacman -Q: "name version"
		parts := strings.Fields(ln)
		if len(parts) < 2 {
			continue
		}
		p := model.PackageEntry{Name: parts[0], Version: parts[1]}
		pkgs = append(pkgs, p)
		if len(pkgs) >= opts.MaxPackages {
			break
		}
	}
	var warns []string
	if truncated {
		warns = append(warns, "package_list_truncated")
	}
	if len(lines) > opts.MaxPackages {
		warns = append(warns, "package_list_capped")
	}
	return pkgs, warns, nil
}

func runAPK(ctx context.Context, opts Options) ([]model.PackageEntry, []string, error) {
	// apk info -vv: "name-version description"
	ctxCmd, cancel := context.WithTimeout(ctx, opts.CmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctxCmd, "apk", "info", "-vv")
	lines, truncated, err := runLimitedLines(cmd, opts.MaxOutputBytes)
	if err != nil {
		return nil, nil, err
	}
	pkgs := make([]model.PackageEntry, 0, minInt(len(lines), opts.MaxPackages))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		// First token is name-version (may contain hyphens); split at last '-'
		first := strings.Fields(ln)
		if len(first) == 0 {
			continue
		}
		nameVer := first[0]
		idx := strings.LastIndex(nameVer, "-")
		if idx <= 0 || idx >= len(nameVer)-1 {
			continue
		}
		name := nameVer[:idx]
		ver := nameVer[idx+1:]
		if name == "" || ver == "" {
			continue
		}
		pkgs = append(pkgs, model.PackageEntry{Name: name, Version: ver})
		if len(pkgs) >= opts.MaxPackages {
			break
		}
	}
	var warns []string
	if truncated {
		warns = append(warns, "package_list_truncated")
	}
	if len(lines) > opts.MaxPackages {
		warns = append(warns, "package_list_capped")
	}
	return pkgs, warns, nil
}

func hashPackages(pkgs []model.PackageEntry) string {
	rows := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		rows = append(rows, fmt.Sprintf("%s\t%s\t%s", p.Name, p.Version, p.Arch))
	}
	sort.Strings(rows)
	h := sha256.New()
	for _, r := range rows {
		_, _ = io.WriteString(h, r)
		_, _ = io.WriteString(h, "\n")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func runLimitedLines(cmd *exec.Cmd, maxBytes int64) ([]string, bool, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, false, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, false, fmt.Errorf("start command: %w", err)
	}

	limited := io.LimitReader(stdout, maxBytes)
	b, readErr := io.ReadAll(limited)
	// Drain stderr (best-effort) for debugging; keep small.
	_, _ = io.ReadAll(io.LimitReader(stderr, 32<<10))

	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, false, fmt.Errorf("read command output: %w", readErr)
	}
	if waitErr != nil {
		if errors.Is(waitErr, context.DeadlineExceeded) {
			return nil, false, fmt.Errorf("command timeout")
		}
		return nil, false, fmt.Errorf("command failed: %w", waitErr)
	}

	truncated := int64(len(b)) >= maxBytes
	lines := splitLines(string(b))
	return lines, truncated, nil
}

func splitLines(s string) []string {
	out := make([]string, 0, 1024)
	scanner := bufio.NewScanner(strings.NewReader(s))
	// Allow long lines (package managers can output large strings)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 512*1024)
	for scanner.Scan() {
		ln := strings.TrimSpace(scanner.Text())
		if ln == "" {
			continue
		}
		out = append(out, ln)
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
