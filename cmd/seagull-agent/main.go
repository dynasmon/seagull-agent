package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/dynasmon/seagull-agent/internal/buildinfo"
	"github.com/dynasmon/seagull-agent/internal/certrenew"
	agentcfg "github.com/dynasmon/seagull-agent/internal/config"
	agentruntime "github.com/dynasmon/seagull-agent/internal/runtime"
	"github.com/dynasmon/seagull-agent/internal/transport"
)

func main() {
	handled, err := executeCommand(os.Args[1:], os.Stdout)
	if err != nil {
		log.Fatalf("[AGENT] command error: %v", err)
	}
	if handled {
		return
	}
	cfg := agentcfg.LoadConfig()
	if err := certrenew.RecoverPair(strings.TrimSpace(cfg.TLSCertFile), strings.TrimSpace(cfg.TLSKeyFile)); err != nil {
		log.Fatalf("[AGENT] TLS client recovery error: %v", err)
	}
	httpClient, err := transport.NewHTTPClient(cfg.HTTPTimeout, transport.TLSOptions{
		CAFile:     strings.TrimSpace(cfg.TLSCAFile),
		CertFile:   strings.TrimSpace(cfg.TLSCertFile),
		KeyFile:    strings.TrimSpace(cfg.TLSKeyFile),
		ServerName: resolveTLSServerName(cfg.APIURL, cfg.TLSServerName),
	})
	if err != nil {
		log.Fatalf("[AGENT] TLS client init error: %v", err)
	}

	log.Printf("[AGENT] version=%s id=%s api=%s sources=%v interval=%s scan_mode=%s",
		buildinfo.String(), cfg.AgentID, cfg.APIURL, cfg.Sources, cfg.Interval, agentcfg.NormalizeScanMode(cfg.ScanMode),
	)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	svc, err := agentruntime.New(rootCtx, cfg, stop, httpClient)
	if err != nil {
		log.Fatalf("[AGENT] init error: %v", err)
	}
	if err := svc.Run(rootCtx); err != nil {
		log.Fatalf("[AGENT] run error: %v", err)
	}
}

func executeCommand(args []string, stdout io.Writer) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "--version", "version":
		if len(args) != 1 {
			return true, errors.New("version does not accept arguments")
		}
		_, err := fmt.Fprintln(stdout, buildinfo.String())
		return true, err
	case "validate-ca":
		if len(args) != 2 {
			return true, errors.New("validate-ca requires one PEM file path")
		}
		bundle, err := os.ReadFile(args[1])
		if err != nil {
			return true, fmt.Errorf("read server CA bundle: %w", err)
		}
		if err := certrenew.ValidateServerCA(string(bundle)); err != nil {
			return true, err
		}
		_, err = fmt.Fprintln(stdout, "valid server CA bundle")
		return true, err
	default:
		return true, fmt.Errorf("unknown command %q", args[0])
	}
}

func resolveTLSServerName(apiURL string, configured string) string {
	if serverName := strings.TrimSpace(configured); serverName != "" {
		return serverName
	}
	parsed, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
