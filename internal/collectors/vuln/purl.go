package vuln

import (
	"net/url"
	"strings"
)

// Reference: https://github.com/package-url/purl-spec
type PURL struct {
	Type      string
	Namespace string
	Name      string
	Version   string
}

// ParsePURL performs a lightweight parse of a purl string.
// It is intentionally minimal and only extracts the fields required for OSV queries.
func ParsePURL(purl string) PURL {
	s := strings.TrimSpace(purl)
	s = strings.TrimPrefix(s, "pkg:")
	if s == purl {
		// Not a purl.
		return PURL{}
	}

	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}

	ver := ""
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		ver = s[i+1:]
		s = s[:i]
	}

	typePart := ""
	rest := ""
	if i := strings.IndexByte(s, '/'); i >= 0 {
		typePart = s[:i]
		rest = s[i+1:]
	} else {
		typePart = s
		rest = ""
	}

	name := ""
	ns := ""
	if rest != "" {
		parts := strings.Split(rest, "/")
		if len(parts) == 1 {
			name = parts[0]
		} else if len(parts) >= 2 {
			name = parts[len(parts)-1]
			ns = strings.Join(parts[:len(parts)-1], "/")
		}
	}

	typePart, _ = url.PathUnescape(typePart)
	name, _ = url.PathUnescape(name)
	ns, _ = url.PathUnescape(ns)
	ver, _ = url.PathUnescape(ver)

	return PURL{
		Type:      strings.TrimSpace(typePart),
		Namespace: strings.TrimSpace(ns),
		Name:      strings.TrimSpace(name),
		Version:   strings.TrimSpace(ver),
	}
}
