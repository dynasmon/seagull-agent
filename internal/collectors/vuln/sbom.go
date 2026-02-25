package vuln

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type SBOMOptions struct {
	SyftPath      string
	Targets       []string
	Timeout       time.Duration
	MaxComponents int

	// Tags to be attached to all SBOM-derived candidates.
	Tags []string
}

type SBOMStats struct {
	TargetsScanned       int
	TargetsSkipped       int
	ComponentsTotal      int
	ComponentsCandidates int
	UniqueCandidates     int
	SBOMHash             string
}

type SBOMCandidate struct {
	Purl     string
	Version  string
	Eco      string
	PkgName  string
	Paths    []string
	Evidence map[string]interface{}
}

// BuildSBOMCandidates generates CycloneDX SBOMs using syft and extracts candidates
// for the OSV query batch (pip/npm/maven/go). It returns a stable hash of the
// candidate set to enable cheap dedup on the agent side.
func BuildSBOMCandidates(ctx context.Context, opts SBOMOptions) ([]SBOMCandidate, SBOMStats, error) {
	var stats SBOMStats
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Minute
	}
	if opts.MaxComponents <= 0 {
		opts.MaxComponents = 20000
	}
	syftPath := strings.TrimSpace(opts.SyftPath)
	if syftPath == "" {
		syftPath = "/usr/local/bin/syft"
	}

	// Validate syft is present.
	if _, err := os.Stat(syftPath); err != nil {
		return nil, stats, fmt.Errorf("syft not found at %s: %w", syftPath, err)
	}

	targets := make([]string, 0, len(opts.Targets))
	for _, t := range opts.Targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return nil, stats, nil
	}

	seen := map[string]*SBOMCandidate{}
	order := make([]string, 0, 1024)
	componentsProcessed := 0

	for _, target := range targets {
		if ctx.Err() != nil {
			return nil, stats, ctx.Err()
		}
		// Skip non-existing targets.
		if _, err := os.Stat(target); err != nil {
			stats.TargetsSkipped++
			continue
		}

		ctxT, cancel := context.WithTimeout(ctx, opts.Timeout)
		out, err := runSyftCycloneDX(ctxT, syftPath, target)
		cancel()
		if err != nil {
			// Best-effort: skip the target but keep scanning others.
			stats.TargetsSkipped++
			continue
		}
		stats.TargetsScanned++

		bom, err := parseCycloneDX(out)
		if err != nil {
			stats.TargetsSkipped++
			continue
		}

		for _, c := range bom.Components {
			stats.ComponentsTotal++
			if componentsProcessed >= opts.MaxComponents {
				return nil, stats, errors.New("sbom component limit exceeded")
			}
			componentsProcessed++

			purl := strings.TrimSpace(c.PURL)
			ver := strings.TrimSpace(c.Version)
			if purl == "" {
				purl = buildPURLFallback(c)
			}
			if purl == "" {
				continue
			}
			p := ParsePURL(purl)
			if p.Type == "" {
				continue
			}
			eco, pkgName, ok := osvFromPURL(p)
			if !ok {
				continue
			}
			if ver == "" {
				ver = strings.TrimSpace(p.Version)
			}
			if ver == "" {
				continue
			}

			stats.ComponentsCandidates++
			key := strings.ToLower(strings.TrimSpace(purl)) + "@" + strings.ToLower(strings.TrimSpace(ver))
			cand, exists := seen[key]
			if !exists {
				cand = &SBOMCandidate{
					Purl:    purl,
					Version: ver,
					Eco:     eco,
					PkgName: pkgName,
					Paths:   []string{},
					Evidence: map[string]interface{}{
						"purl":    purl,
						"version": ver,
						"name":    c.Name,
					},
				}
				seen[key] = cand
				order = append(order, key)
			}
			cand.Paths = append(cand.Paths, target)
		}
	}

	// Make candidates deterministic.
	sort.Strings(order)
	out := make([]SBOMCandidate, 0, len(order))
	for _, k := range order {
		cand := seen[k]
		if cand == nil {
			continue
		}
		sort.Strings(cand.Paths)
		// Merge paths into evidence.
		cand.Evidence["paths"] = cand.Paths
		out = append(out, *cand)
	}
	stats.UniqueCandidates = len(out)

	// Stable hash of the candidate set enables quick skip when unchanged.
	h := sha256.New()
	for _, c := range out {
		io.WriteString(h, strings.ToLower(strings.TrimSpace(c.Purl)))
		io.WriteString(h, "@")
		io.WriteString(h, strings.ToLower(strings.TrimSpace(c.Version)))
		io.WriteString(h, "\n")
	}
	stats.SBOMHash = hex.EncodeToString(h.Sum(nil))
	return out, stats, nil
}

func runSyftCycloneDX(ctx context.Context, syftPath, target string) ([]byte, error) {
	// Use absolute paths when possible for more consistent results.
	if abs, err := filepath.Abs(target); err == nil {
		target = abs
	}

	// syft output can be large; enforce a hard cap.
	const maxOut = 64 << 20
	cmd := exec.CommandContext(ctx, syftPath, fmt.Sprintf("dir:%s", target), "-o", "cyclonedx-json")
	cmd.Env = append(os.Environ(),
		"SYFT_CHECK_FOR_APP_UPDATE=false",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	out, _ := io.ReadAll(io.LimitReader(stdout, maxOut))
	// Drain stderr (also capped) for completion.
	_, _ = io.ReadAll(io.LimitReader(stderr, 1<<20))

	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("empty syft output")
	}
	return out, nil
}

type cyclonedxBOM struct {
	Components []cyclonedxComponent `json:"components"`
}

type cyclonedxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Group   string `json:"group"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

func parseCycloneDX(b []byte) (cyclonedxBOM, error) {
	var bom cyclonedxBOM
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bom); err == nil {
		return bom, nil
	}
	// Fallback: allow unknown fields because syft adds many extras.
	var bom2 cyclonedxBOM
	if err := json.Unmarshal(b, &bom2); err != nil {
		return cyclonedxBOM{}, err
	}
	return bom2, nil
}

func buildPURLFallback(c cyclonedxComponent) string {
	name := strings.TrimSpace(c.Name)
	ver := strings.TrimSpace(c.Version)
	group := strings.TrimSpace(c.Group)
	if name == "" || ver == "" {
		return ""
	}
	// Maven packages typically use group+name.
	if group != "" {
		return fmt.Sprintf("pkg:maven/%s/%s@%s", urlEscape(group), urlEscape(name), urlEscape(ver))
	}
	return ""
}

func urlEscape(s string) string {
	// Minimal escaping for purl components.
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, " ", "%20")
	s = strings.ReplaceAll(s, "/", "%2F")
	return s
}

func osvFromPURL(p PURL) (string, string, bool) {
	// OSV ecosystems: PyPI, npm, Maven, Go.
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "pypi":
		return "PyPI", strings.ToLower(p.Name), true
	case "npm":
		if p.Namespace != "" {
			return "npm", "@" + p.Namespace + "/" + p.Name, true
		}
		return "npm", p.Name, true
	case "maven":
		if p.Namespace != "" {
			return "Maven", p.Namespace + ":" + p.Name, true
		}
		return "Maven", p.Name, true
	case "golang", "go":
		if p.Namespace != "" {
			return "Go", p.Namespace + "/" + p.Name, true
		}
		return "Go", p.Name, true
	default:
		return "", "", false
	}
}
