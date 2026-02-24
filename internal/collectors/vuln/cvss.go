package vuln

import (
	"math"
	"strings"
)

// CVSSv3BaseScore computes the CVSS v3.x base score from a vector string.
// It supports vectors like: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
func CVSSv3BaseScore(vector string) (float64, bool) {
	v := strings.TrimSpace(vector)
	up := strings.ToUpper(v)
	if !strings.HasPrefix(up, "CVSS:3.") {
		return 0, false
	}
	parts := strings.Split(v, "/")
	if len(parts) < 2 {
		return 0, false
	}

	metrics := map[string]string{}
	for _, p := range parts[1:] {
		k, val, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		k = strings.ToUpper(strings.TrimSpace(k))
		val = strings.ToUpper(strings.TrimSpace(val))
		if k != "" && val != "" {
			metrics[k] = val
		}
	}

	av, ok := cvssAV(metrics["AV"])
	if !ok {
		return 0, false
	}
	ac, ok := cvssAC(metrics["AC"])
	if !ok {
		return 0, false
	}
	ui, ok := cvssUI(metrics["UI"])
	if !ok {
		return 0, false
	}
	scope := metrics["S"]
	if scope != "U" && scope != "C" {
		return 0, false
	}
	pr, ok := cvssPR(metrics["PR"], scope)
	if !ok {
		return 0, false
	}
	c, ok := cvssCIA(metrics["C"])
	if !ok {
		return 0, false
	}
	i, ok := cvssCIA(metrics["I"])
	if !ok {
		return 0, false
	}
	a, ok := cvssCIA(metrics["A"])
	if !ok {
		return 0, false
	}

	iss := 1.0 - (1.0-c)*(1.0-i)*(1.0-a)
	impact := 0.0
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15.0)
	}

	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0.0, true
	}

	base := 0.0
	if scope == "U" {
		base = impact + exploitability
	} else {
		base = 1.08 * (impact + exploitability)
	}
	if base > 10.0 {
		base = 10.0
	}
	return roundUp1Decimal(base), true
}

func cvssAV(v string) (float64, bool) {
	switch v {
	case "N":
		return 0.85, true
	case "A":
		return 0.62, true
	case "L":
		return 0.55, true
	case "P":
		return 0.20, true
	default:
		return 0, false
	}
}

func cvssAC(v string) (float64, bool) {
	switch v {
	case "L":
		return 0.77, true
	case "H":
		return 0.44, true
	default:
		return 0, false
	}
}

func cvssPR(v string, scope string) (float64, bool) {
	// Values differ when Scope=Changed.
	if scope == "U" {
		switch v {
		case "N":
			return 0.85, true
		case "L":
			return 0.62, true
		case "H":
			return 0.27, true
		default:
			return 0, false
		}
	}
	if scope == "C" {
		switch v {
		case "N":
			return 0.85, true
		case "L":
			return 0.68, true
		case "H":
			return 0.50, true
		default:
			return 0, false
		}
	}
	return 0, false
}

func cvssUI(v string) (float64, bool) {
	switch v {
	case "N":
		return 0.85, true
	case "R":
		return 0.62, true
	default:
		return 0, false
	}
}

func cvssCIA(v string) (float64, bool) {
	switch v {
	case "H":
		return 0.56, true
	case "L":
		return 0.22, true
	case "N":
		return 0.0, true
	default:
		return 0, false
	}
}
