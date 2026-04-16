package syscollector

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
)

// parseDpkgStatus reads /var/lib/dpkg/status and extracts installed packages.
// It is intentionally conservative: it only includes packages with "install ok installed".
func parseDpkgStatus(path string, maxBytes int64, maxPkgs int) ([]model.PackageEntry, []string, error) {
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	if maxPkgs <= 0 {
		maxPkgs = 50000
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	r := io.LimitReader(f, maxBytes)
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 512*1024)

	var warns []string
	var pkgs []model.PackageEntry

	cur := map[string]string{}
	flush := func() {
		if len(cur) == 0 {
			return
		}
		name := strings.TrimSpace(cur["package"])
		ver := strings.TrimSpace(cur["version"])
		arch := strings.TrimSpace(cur["architecture"])
		status := strings.TrimSpace(cur["status"])
		if name == "" || ver == "" {
			cur = map[string]string{}
			return
		}
		// Only include installed packages.
		if !strings.Contains(status, "install") || !strings.Contains(status, "installed") {
			cur = map[string]string{}
			return
		}
		pkgs = append(pkgs, model.PackageEntry{Name: name, Version: ver, Arch: arch})
		cur = map[string]string{}
	}

	for scanner.Scan() {
		ln := scanner.Text()
		if strings.TrimSpace(ln) == "" {
			flush()
			if len(pkgs) >= maxPkgs {
				warns = append(warns, "package_list_capped")
				break
			}
			continue
		}
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k != "" {
			cur[k] = v
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, warns, err
	}
	// Final stanza (if file doesn't end with blank line)
	flush()

	// If file likely truncated by limit.
	if _, err := f.Seek(0, io.SeekEnd); err == nil {
		// Can't reliably detect truncation after streaming, so keep silent.
		_ = err
	}

	return pkgs, warns, nil
}

// parseApkInstalled reads /lib/apk/db/installed from an Alpine root.
// The format uses single-letter keys per line (P=name, V=version, A=arch).
func parseApkInstalled(path string, maxBytes int64, maxPkgs int) ([]model.PackageEntry, []string, error) {
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	if maxPkgs <= 0 {
		maxPkgs = 50000
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	r := io.LimitReader(f, maxBytes)
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 512*1024)

	var warns []string
	pkgs := make([]model.PackageEntry, 0, 4096)

	name, ver, arch := "", "", ""
	flush := func() {
		if name != "" && ver != "" {
			pkgs = append(pkgs, model.PackageEntry{Name: name, Version: ver, Arch: arch})
		}
		name, ver, arch = "", "", ""
	}

	for scanner.Scan() {
		ln := strings.TrimSpace(scanner.Text())
		if ln == "" {
			flush()
			if len(pkgs) >= maxPkgs {
				warns = append(warns, "package_list_capped")
				break
			}
			continue
		}
		if len(ln) < 2 || ln[1] != ':' {
			continue
		}
		switch ln[0] {
		case 'P':
			name = strings.TrimSpace(ln[2:])
		case 'V':
			ver = strings.TrimSpace(ln[2:])
		case 'A':
			arch = strings.TrimSpace(ln[2:])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, warns, err
	}
	flush()
	return pkgs, warns, nil
}

// parsePacmanLocal reads /var/lib/pacman/local/*/desc.
func parsePacmanLocal(dir string, maxPkgs int) ([]model.PackageEntry, []string, error) {
	if maxPkgs <= 0 {
		maxPkgs = 50000
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	pkgs := make([]model.PackageEntry, 0, minInt(len(entries), maxPkgs))
	var warns []string

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		descPath := filepath.Join(dir, e.Name(), "desc")
		b, err := os.ReadFile(descPath)
		if err != nil {
			continue
		}
		name, ver, arch := parsePacmanDesc(string(b))
		if name == "" || ver == "" {
			continue
		}
		pkgs = append(pkgs, model.PackageEntry{Name: name, Version: ver, Arch: arch})
		if len(pkgs) >= maxPkgs {
			warns = append(warns, "package_list_capped")
			break
		}
	}

	return pkgs, warns, nil
}

func parsePacmanDesc(s string) (name, ver, arch string) {
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); i++ {
		ln := strings.TrimSpace(lines[i])
		switch ln {
		case "%NAME%":
			if i+1 < len(lines) {
				name = strings.TrimSpace(lines[i+1])
			}
		case "%VERSION%":
			if i+1 < len(lines) {
				ver = strings.TrimSpace(lines[i+1])
			}
		case "%ARCH%":
			if i+1 < len(lines) {
				arch = strings.TrimSpace(lines[i+1])
			}
		}
	}
	return
}

func runRPMWithDBPath(ctx context.Context, opts Options, dbPath string) ([]model.PackageEntry, []string, error) {
	ctxCmd, cancel := context.WithTimeout(ctx, opts.CmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctxCmd, "rpm", "--dbpath", dbPath, "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n")
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

func (o Options) validate() error {
	if o.CmdTimeout <= 0 {
		return errors.New("cmd_timeout must be > 0")
	}
	return nil
}

// best-effort helper for systemd / diagnostics.
func (o Options) debugString() string {
	return fmt.Sprintf("cmd_timeout=%s max_output_bytes=%d max_packages=%d host_root=%s", o.CmdTimeout, o.MaxOutputBytes, o.MaxPackages, strings.TrimSpace(o.HostRoot))
}

// Make sure Options.validate() isn't optimized away in older compilers.
var _ = time.Second
