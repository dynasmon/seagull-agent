package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/dynasmon/seagull-agent/protocol"
)

var (
	Version   = ""
	Commit    = ""
	BuildDate = ""
	Channel   = ""
)

const (
	devVersion = "0.0.0-dev"
	devChannel = "dev"
)

var resolveOnce sync.Once

func resolve() {
	resolveOnce.Do(func() {
		revision, modified := vcsStamp()
		if strings.TrimSpace(Commit) == "" {
			Commit = revision
		}
		if strings.TrimSpace(Commit) == "" {
			Commit = "unknown"
		}
		if strings.TrimSpace(Version) == "" {
			Version = devVersion
			if modified {
				Version = devVersion + "+dirty"
			}
		}
		if strings.TrimSpace(Channel) == "" {
			Channel = devChannel
		}
	})
}

func vcsStamp() (string, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false
	}
	revision := ""
	modified := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	return revision, modified
}

func Release() string {
	resolve()
	return Version
}

func Revision() string {
	resolve()
	return Commit
}

func ReleaseChannel() string {
	resolve()
	return Channel
}

func String() string {
	resolve()
	return fmt.Sprintf("seagull-agent %s (%s, %s, %s/%s, protocol %d, event schema %d)",
		Version, Commit, Channel, runtime.GOOS, runtime.GOARCH, protocol.Version, protocol.EventSchemaVersion)
}

func Summary() map[string]interface{} {
	resolve()
	return map[string]interface{}{
		"version":              Version,
		"commit":               Commit,
		"build_date":           BuildDate,
		"channel":              Channel,
		"os":                   runtime.GOOS,
		"arch":                 runtime.GOARCH,
		"protocol_version":     protocol.Version,
		"min_server_protocol":  protocol.MinSupportedServer,
		"max_server_protocol":  protocol.MaxSupportedServer,
		"event_schema_version": protocol.EventSchemaVersion,
		"min_event_schema":     protocol.MinEventSchema,
		"max_event_schema":     protocol.MaxEventSchema,
	}
}
