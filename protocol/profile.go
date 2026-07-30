package protocol

import "strings"

const (
	ProfileSensor  = "sensor"
	ProfileManaged = "managed"
)

func NormalizeProfile(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case ProfileManaged:
		return ProfileManaged
	default:
		return ProfileSensor
	}
}

func ProfileAllowsResponseActions(profile string) bool {
	return NormalizeProfile(profile) == ProfileManaged
}
