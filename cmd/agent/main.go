package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/buildinfo"
	agentcfg "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/config"
	agentruntime "gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/runtime"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/transport"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println(buildinfo.String())
		return
	}
	cfg := agentcfg.LoadConfig()
	httpClient, err := transport.NewHTTPClient(cfg.HTTPTimeout, transport.TLSOptions{
		CAFile:     strings.TrimSpace(cfg.TLSCAFile),
		CertFile:   strings.TrimSpace(cfg.TLSCertFile),
		KeyFile:    strings.TrimSpace(cfg.TLSKeyFile),
		ServerName: strings.TrimSpace(cfg.TLSServerName),
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
