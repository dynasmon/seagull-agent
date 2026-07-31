package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

type component struct {
	Type       string     `json:"type"`
	BOMRef     string     `json:"bom-ref"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	PURL       string     `json:"purl,omitempty"`
	Hashes     []hashRef  `json:"hashes,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type hashRef struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type metadata struct {
	Tools     []component `json:"tools"`
	Component component   `json:"component"`
}

type document struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    metadata    `json:"metadata"`
	Components  []component `json:"components"`
}

func main() {
	binary := flag.String("binary", "", "path to the built binary")
	name := flag.String("name", "seagull-agent", "product name")
	version := flag.String("version", "", "product version")
	out := flag.String("out", "", "output path for the CycloneDX document")
	flag.Parse()

	if strings.TrimSpace(*binary) == "" || strings.TrimSpace(*out) == "" {
		fmt.Fprintln(os.Stderr, "sbom: --binary and --out are required")
		os.Exit(2)
	}

	modules, goVersion, err := readBuildModules(*binary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		os.Exit(1)
	}

	digest, err := fileDigest(*binary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		os.Exit(1)
	}

	doc := document{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: metadata{
			Tools: []component{{
				Type:    "application",
				BOMRef:  "tool/seagull-sbom",
				Name:    "seagull-sbom",
				Version: goVersion,
			}},
			Component: component{
				Type:    "application",
				BOMRef:  "pkg:golang/github.com/dynasmon/Seagull-agent@" + *version,
				Name:    *name,
				Version: *version,
				PURL:    "pkg:golang/github.com/dynasmon/Seagull-agent@" + *version,
				Hashes:  []hashRef{{Alg: "SHA-256", Content: digest}},
				Properties: []property{
					{Name: "seagull:go.version", Value: goVersion},
				},
			},
		},
		Components: modules,
	}

	payload, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, append(payload, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		os.Exit(1)
	}
}

func readBuildModules(binary string) ([]component, string, error) {
	cmd := exec.Command("go", "version", "-m", binary)
	output, err := cmd.Output()
	if err != nil {
		return nil, "", fmt.Errorf("read build metadata from %s: %w", binary, err)
	}

	goVersion := ""
	seen := make(map[string]component)
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if goVersion == "" && strings.Contains(trimmed, ": go") {
			parts := strings.Fields(trimmed)
			goVersion = parts[len(parts)-1]
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}
		switch fields[0] {
		case "dep", "mod":
			path, moduleVersion := fields[1], fields[2]
			if path == "" || moduleVersion == "" || moduleVersion == "(devel)" {
				continue
			}
			ref := "pkg:golang/" + path + "@" + moduleVersion
			entry := component{
				Type:    "library",
				BOMRef:  ref,
				Name:    path,
				Version: moduleVersion,
				PURL:    ref,
			}
			if len(fields) >= 5 && strings.HasPrefix(fields[3], "h1:") {
				entry.Properties = append(entry.Properties, property{Name: "go:mod:h1", Value: fields[3]})
			}
			seen[ref] = entry
		}
	}

	refs := make([]string, 0, len(seen))
	for ref := range seen {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	components := make([]component, 0, len(refs))
	for _, ref := range refs {
		components = append(components, seen[ref])
	}
	return components, goVersion, nil
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}
