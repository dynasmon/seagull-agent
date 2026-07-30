package agentcfg

import (
	"encoding/json"
	"log"
	"strings"
	"time"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

func LogJSON(level LogLevel, msg string, fields map[string]interface{}) {
	fields["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["level"] = LevelString(level)
	fields["msg"] = msg

	b, err := json.Marshal(fields)
	if err != nil {
		log.Printf("[LOG] marshal_error=%v msg=%s", err, msg)
		return
	}
	log.Println(string(b))
}

func ParseLogLevel(s string) LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func LevelString(l LogLevel) string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}
