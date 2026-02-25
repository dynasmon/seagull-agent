package vuln

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/model"
)

type OSVOptions struct {
	BaseURL        string
	Ecosystem      string
	MinSeverity    string
	BatchSize      int
	HTTPTimeout    time.Duration
	AssetKey       string
	AssetAgentID   string
	TargetLabel    string
	OS             map[string]interface{}
	PackageManager string
}

type OSVStats struct {
	QueriedPackages int
	ReceivedVulns   int
	EmittedFindings int
}

type osvQueryBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Purl      string `json:"purl,omitempty"`
}

type osvQueryBatchResponse struct {
	Results []osvQueryResult `json:"results"`
}

type osvQueryResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Aliases  []string      `json:"aliases"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package osvPackage `json:"package"`
	Ranges  []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string      `json:"type"`
	Events []osvEvent  `json:"events"`
	Repo   string      `json:"repo"`
	DBSpec interface{} `json:"database_specific"`
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type PURLQueryItem struct {
	Purl     string
	Version  string
	Eco      string
	PkgName  string
	Evidence map[string]interface{}
	Tags     []string
}

func QueryOSV(ctx context.Context, pkgs []model.PackageEntry, opts OSVOptions) ([]Finding, OSVStats, error) {
	var stats OSVStats
	if opts.BatchSize <= 0 {
		opts.BatchSize = 200
	}
	if opts.HTTPTimeout <= 0 {
		opts.HTTPTimeout = 20 * time.Second
	}
	baseURL := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.osv.dev"
	}
	endpoint := baseURL + "/v1/querybatch"

	minRank := severityRank(strings.TrimSpace(opts.MinSeverity))
	if minRank < 0 {
		minRank = 0
	}

	client := &http.Client{Timeout: opts.HTTPTimeout}

	// Deterministic order improves reproducibility and stable pagination in logs.
	pkgs2 := make([]model.PackageEntry, 0, len(pkgs))
	for _, p := range pkgs {
		name := strings.TrimSpace(p.Name)
		ver := strings.TrimSpace(p.Version)
		if name == "" || ver == "" {
			continue
		}
		pkgs2 = append(pkgs2, model.PackageEntry{Name: name, Version: ver, Arch: strings.TrimSpace(p.Arch)})
	}
	sort.Slice(pkgs2, func(i, j int) bool {
		if pkgs2[i].Name == pkgs2[j].Name {
			return pkgs2[i].Version < pkgs2[j].Version
		}
		return pkgs2[i].Name < pkgs2[j].Name
	})

	findings := make([]Finding, 0, 256)

	for i := 0; i < len(pkgs2); i += opts.BatchSize {
		j := i + opts.BatchSize
		if j > len(pkgs2) {
			j = len(pkgs2)
		}
		batch := pkgs2[i:j]
		stats.QueriedPackages += len(batch)

		reqBody := osvQueryBatchRequest{Queries: make([]osvQuery, 0, len(batch))}
		for _, p := range batch {
			reqBody.Queries = append(reqBody.Queries, osvQuery{
				Package: osvPackage{Name: p.Name, Ecosystem: strings.TrimSpace(opts.Ecosystem)},
				Version: p.Version,
			})
		}

		b, err := json.Marshal(reqBody)
		if err != nil {
			return findings, stats, fmt.Errorf("marshal osv query batch: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
		if err != nil {
			return findings, stats, fmt.Errorf("new osv request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return findings, stats, fmt.Errorf("osv request failed: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return findings, stats, fmt.Errorf("osv returned status=%d", resp.StatusCode)
		}

		var out osvQueryBatchResponse
		if err := json.Unmarshal(body, &out); err != nil {
			return findings, stats, fmt.Errorf("unmarshal osv response: %w", err)
		}
		// OSV preserves the order of queries.
		for idx, r := range out.Results {
			if idx < 0 || idx >= len(batch) {
				continue
			}
			pkg := batch[idx]
			if len(r.Vulns) == 0 {
				continue
			}
			for _, v := range r.Vulns {
				stats.ReceivedVulns++

				sev, cvssStr := deriveSeverity(v)
				rank := severityRank(sev)
				if rank < minRank {
					continue
				}

				cve := pickCVE(v.Aliases)
				title := strings.TrimSpace(v.Summary)
				if title == "" {
					title = strings.TrimSpace(cve)
				}
				if title == "" {
					title = "vulnerability detected"
				}

				details := strings.TrimSpace(v.Details)
				if len(details) > 16000 {
					details = details[:16000]
				}

				rem := buildRemediation(pkg, v)

				asset := map[string]interface{}{}
				for k, vv := range opts.OS {
					asset[k] = vv
				}
				asset["package"] = map[string]interface{}{
					"name":      pkg.Name,
					"version":   pkg.Version,
					"arch":      pkg.Arch,
					"manager":   opts.PackageManager,
					"ecosystem": strings.TrimSpace(opts.Ecosystem),
				}

				fp := stableFingerprint(opts.AssetKey, "osv", v.ID, strings.TrimSpace(opts.Ecosystem), pkg.Name)

				now := time.Now().UTC()
				f := Finding{
					AssetKey:     opts.AssetKey,
					AssetAgentID: opts.AssetAgentID,
					Target:       opts.TargetLabel,
					Asset:        asset,

					Source:      "osv",
					ExternalID:  strings.TrimSpace(v.ID),
					Fingerprint: fp,

					Severity:   sev,
					Confidence: 90,

					Title:       title,
					Description: details,
					Remediation: rem,

					CVE:  cve,
					CVSS: cvssStr,

					Location: fmt.Sprintf("pkg:%s", pkg.Name),
					Tags:     uniqTags([]string{"package", "osv", opts.PackageManager, strings.ToLower(strings.TrimSpace(opts.Ecosystem))}),
					Evidence: buildEvidence(pkg, v),

					LastSeenAt: &now,
				}

				findings = append(findings, f)
				stats.EmittedFindings++
			}
		}
	}

	return findings, stats, nil
}

// QueryOSVByPURLs queries OSV using purls extracted from SBOMs (CycloneDX).
// It supports application dependencies across ecosystems (pip/npm/maven/go).
func QueryOSVByPURLs(ctx context.Context, items []PURLQueryItem, opts OSVOptions) ([]Finding, OSVStats, error) {
	var stats OSVStats
	if opts.BatchSize <= 0 {
		opts.BatchSize = 200
	}
	if opts.HTTPTimeout <= 0 {
		opts.HTTPTimeout = 20 * time.Second
	}
	baseURL := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.osv.dev"
	}
	endpoint := baseURL + "/v1/querybatch"

	minRank := severityRank(strings.TrimSpace(opts.MinSeverity))
	if minRank < 0 {
		minRank = 0
	}

	client := &http.Client{Timeout: opts.HTTPTimeout}

	// Deterministic order improves reproducibility.
	items2 := make([]PURLQueryItem, 0, len(items))
	for _, it := range items {
		p := strings.TrimSpace(it.Purl)
		v := strings.TrimSpace(it.Version)
		if p == "" {
			continue
		}
		items2 = append(items2, it)
		_ = v
	}
	sort.Slice(items2, func(i, j int) bool {
		pi := strings.ToLower(items2[i].Purl)
		pj := strings.ToLower(items2[j].Purl)
		if pi == pj {
			return strings.ToLower(items2[i].Version) < strings.ToLower(items2[j].Version)
		}
		return pi < pj
	})

	findings := make([]Finding, 0, 256)

	for i := 0; i < len(items2); i += opts.BatchSize {
		j := i + opts.BatchSize
		if j > len(items2) {
			j = len(items2)
		}
		batch := items2[i:j]
		stats.QueriedPackages += len(batch)

		reqBody := osvQueryBatchRequest{Queries: make([]osvQuery, 0, len(batch))}
		for _, it := range batch {
			q := osvQuery{Package: osvPackage{Purl: strings.TrimSpace(it.Purl)}}
			if s := strings.TrimSpace(it.Version); s != "" {
				q.Version = s
			}
			reqBody.Queries = append(reqBody.Queries, q)
		}

		b, err := json.Marshal(reqBody)
		if err != nil {
			return findings, stats, fmt.Errorf("marshal osv query batch: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
		if err != nil {
			return findings, stats, fmt.Errorf("new osv request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return findings, stats, fmt.Errorf("osv request failed: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return findings, stats, fmt.Errorf("osv returned status=%d", resp.StatusCode)
		}

		var out osvQueryBatchResponse
		if err := json.Unmarshal(body, &out); err != nil {
			return findings, stats, fmt.Errorf("unmarshal osv response: %w", err)
		}

		for idx, r := range out.Results {
			if idx < 0 || idx >= len(batch) {
				continue
			}
			it := batch[idx]
			if len(r.Vulns) == 0 {
				continue
			}
			for _, v := range r.Vulns {
				stats.ReceivedVulns++
				sev, cvssStr := deriveSeverity(v)
				rank := severityRank(sev)
				if rank < minRank {
					continue
				}

				cve := pickCVE(v.Aliases)
				title := strings.TrimSpace(v.Summary)
				if title == "" {
					title = strings.TrimSpace(cve)
				}
				if title == "" {
					title = "vulnerability detected"
				}

				details := strings.TrimSpace(v.Details)
				if len(details) > 16000 {
					details = details[:16000]
				}

				rem := buildRemediationForAppDep(it, v)

				asset := map[string]interface{}{}
				for k, vv := range opts.OS {
					asset[k] = vv
				}
				asset["component"] = map[string]interface{}{
					"purl":      strings.TrimSpace(it.Purl),
					"version":   strings.TrimSpace(it.Version),
					"ecosystem": strings.TrimSpace(it.Eco),
					"name":      strings.TrimSpace(it.PkgName),
				}

				fp := stableFingerprintParts(opts.AssetKey, "osv", v.ID, strings.TrimSpace(it.Purl), strings.TrimSpace(it.Version))

				now := time.Now().UTC()
				evidence := map[string]interface{}{}
				for k, vv := range it.Evidence {
					evidence[k] = vv
				}
				evidence["osv"] = map[string]interface{}{
					"id":      v.ID,
					"aliases": v.Aliases,
				}
				if s := strings.TrimSpace(v.Summary); s != "" {
					evidence["osv"].(map[string]interface{})["summary"] = s
				}
				if fix := firstFixedVersion(v); fix != "" {
					evidence["osv"].(map[string]interface{})["fixed"] = fix
				}

				loc := strings.TrimSpace(it.Purl)
				if loc == "" {
					loc = strings.TrimSpace(it.PkgName)
				}

				f := Finding{
					AssetKey:     opts.AssetKey,
					AssetAgentID: opts.AssetAgentID,
					Target:       opts.TargetLabel,
					Asset:        asset,

					Source:      "osv",
					ExternalID:  strings.TrimSpace(v.ID),
					Fingerprint: fp,

					Severity:   sev,
					Confidence: 90,

					Title:       title,
					Description: details,
					Remediation: rem,

					CVE:  cve,
					CVSS: cvssStr,

					Location: loc,
					Tags:     uniqTags(append([]string{"sbom", "appdep", "osv"}, it.Tags...)),
					Evidence: evidence,

					LastSeenAt: &now,
				}

				findings = append(findings, f)
				stats.EmittedFindings++
			}
		}
	}

	return findings, stats, nil
}

func stableFingerprint(assetKey, source, externalID, ecosystem, pkgName string) string {
	return stableFingerprintParts(assetKey, source, externalID, ecosystem, pkgName)
}

func stableFingerprintParts(parts ...string) string {
	b := strings.Builder{}
	for i, p := range parts {
		if i > 0 {
			b.WriteString("|")
		}
		b.WriteString(strings.ToLower(strings.TrimSpace(p)))
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

func buildRemediationForAppDep(it PURLQueryItem, v osvVuln) string {
	name := strings.TrimSpace(it.PkgName)
	if name == "" {
		name = strings.TrimSpace(it.Purl)
	}
	fixed := firstFixedVersion(v)
	if fixed != "" {
		return fmt.Sprintf("Upgrade %s to >= %s", name, fixed)
	}
	return fmt.Sprintf("Upgrade %s to a non-vulnerable version", name)
}

func pickCVE(aliases []string) string {
	for _, a := range aliases {
		a = strings.TrimSpace(a)
		if strings.HasPrefix(strings.ToUpper(a), "CVE-") {
			return strings.ToUpper(a)
		}
	}
	return ""
}

func uniqTags(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t2 := strings.ToLower(strings.TrimSpace(t))
		if t2 == "" {
			continue
		}
		if len(t2) > 64 {
			t2 = t2[:64]
		}
		if seen[t2] {
			continue
		}
		seen[t2] = true
		out = append(out, t2)
	}
	return out
}

func severityRank(sev string) int {
	s := strings.ToLower(strings.TrimSpace(sev))
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "info", "informational", "none", "unknown":
		return 0
	default:
		return 0
	}
}

func deriveSeverity(v osvVuln) (string, string) {
	// Prefer CVSS vector if present.
	for _, s := range v.Severity {
		if strings.Contains(strings.ToUpper(s.Type), "CVSS") {
			vec := strings.TrimSpace(s.Score)
			if vec != "" {
				if score, ok := CVSSv3BaseScore(vec); ok {
					return severityFromScore(score), vec
				}
				// Fallback: keep the vector string even when parsing fails.
				return "unknown", vec
			}
		}
	}
	// Heuristic: use alias presence.
	if pickCVE(v.Aliases) != "" {
		return "high", ""
	}
	return "unknown", ""
}

func severityFromScore(score float64) string {
	if score >= 9.0 {
		return "critical"
	}
	if score >= 7.0 {
		return "high"
	}
	if score >= 4.0 {
		return "medium"
	}
	if score > 0.0 {
		return "low"
	}
	return "unknown"
}

func buildRemediation(pkg model.PackageEntry, v osvVuln) string {
	fixed := firstFixedVersion(v)
	if fixed != "" {
		return fmt.Sprintf("Upgrade %s to >= %s", pkg.Name, fixed)
	}
	return fmt.Sprintf("Upgrade %s to a non-vulnerable version", pkg.Name)
}

func firstFixedVersion(v osvVuln) string {
	for _, aff := range v.Affected {
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if strings.TrimSpace(ev.Fixed) != "" {
					return strings.TrimSpace(ev.Fixed)
				}
			}
		}
	}
	return ""
}

func buildEvidence(pkg model.PackageEntry, v osvVuln) map[string]interface{} {
	e := map[string]interface{}{
		"package": map[string]interface{}{
			"name":    pkg.Name,
			"version": pkg.Version,
			"arch":    pkg.Arch,
		},
		"osv": map[string]interface{}{
			"id":      v.ID,
			"aliases": v.Aliases,
		},
	}
	if s := strings.TrimSpace(v.Summary); s != "" {
		e["osv"].(map[string]interface{})["summary"] = s
	}
	if fix := firstFixedVersion(v); fix != "" {
		e["osv"].(map[string]interface{})["fixed"] = fix
	}
	return e
}

// Round up to 1 decimal as defined by CVSS v3.x.
func roundUp1Decimal(x float64) float64 {
	return math.Ceil(x*10.0) / 10.0
}
