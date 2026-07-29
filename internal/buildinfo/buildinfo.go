package buildinfo

import (
	"fmt"
	"runtime"
)

var (
	Version   = "0.0.0-dev"
	Commit    = "unknown"
	BuildDate = ""
	Channel   = "dev"
)

const (
	ProtocolVersion    = 1
	MinProtocolVersion = 1
	MaxProtocolVersion = 1
	EventSchemaVersion = 1
)

func String() string {
	return fmt.Sprintf("%s (%s, %s/%s, protocol %d)", Version, Commit, runtime.GOOS, runtime.GOARCH, ProtocolVersion)
}

func Summary() map[string]interface{} {
	return map[string]interface{}{
		"version":              Version,
		"commit":               Commit,
		"build_date":           BuildDate,
		"channel":              Channel,
		"os":                   runtime.GOOS,
		"arch":                 runtime.GOARCH,
		"protocol_version":     ProtocolVersion,
		"event_schema_version": EventSchemaVersion,
	}
}
