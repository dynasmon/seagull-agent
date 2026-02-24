package vuln

import "strings"

// InferEcosystem derives a best-effort OSV ecosystem name from syscollector fields.
// The mapping is intentionally conservative; unknown OS/distro will fallback to "".
func InferEcosystem(manager string, osInfo map[string]interface{}) string {
	m := strings.ToLower(strings.TrimSpace(manager))
	osID := strings.ToLower(strings.TrimSpace(toString(osInfo["id"])))
	osName := strings.ToLower(strings.TrimSpace(toString(osInfo["name"])))
	osLike := strings.ToLower(strings.TrimSpace(toString(osInfo["id_like"])))

	switch m {
	case "apk":
		return "Alpine"
	case "pacman":
		return "Arch Linux"
	case "dpkg":
		if osID == "ubuntu" || strings.Contains(osName, "ubuntu") {
			return "Ubuntu"
		}
		if osID == "debian" || strings.Contains(osLike, "debian") {
			return "Debian"
		}
		// Fallback for Debian-like.
		return "Debian"
	case "rpm":
		// Common rpm distros.
		switch osID {
		case "fedora":
			return "Fedora"
		case "rhel", "redhat":
			return "Red Hat"
		case "centos":
			return "CentOS"
		case "rocky":
			return "Rocky Linux"
		case "almalinux":
			return "AlmaLinux"
		case "ol":
			return "Oracle Linux"
		case "opensuse", "sles", "suse":
			return "SUSE"
		default:
			if strings.Contains(osLike, "rhel") || strings.Contains(osLike, "fedora") {
				return "Red Hat"
			}
		}
	}

	return ""
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
