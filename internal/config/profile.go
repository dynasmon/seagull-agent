package agentcfg

import "strings"

const (
	ProfileSensor  = "sensor"
	ProfileManaged = "managed"
)

func NormalizeProfile(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ProfileSensor:
		return ProfileSensor
	case ProfileManaged:
		return ProfileManaged
	default:
		return ProfileManaged
	}
}

func ProfileAllowsResponseActions(profile string) bool {
	return NormalizeProfile(profile) != ProfileSensor
}
