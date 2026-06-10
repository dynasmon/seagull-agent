package agentcfg

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultL7Sources         = "authlog,proc,proc_exec,fim,scan,ddos,l7"
	DefaultL7DedupTTL        = 20 * time.Second
	DefaultL7MaxBatch        = 400
	DefaultL7MaxPayloadBytes = 512
	MaxL7MaxBatch            = 2000
	MaxL7MaxPayloadBytes     = 4096
)

type Config struct {
	AgentID        string
	APIURL         string
	Sources        []string
	Interval       time.Duration
	HTTPTimeout    time.Duration
	SenderMaxBatch int

	AgentConfigFile               string
	AgentIdentityStateFile        string
	BootstrapToken                string
	BootstrapTokenFile            string
	AgentCredential               string
	AgentCredentialExpiresAt      string
	CredentialFile                string
	RenewalToken                  string
	RenewalTokenExpiresAt         string
	PreviousRenewalToken          string
	PreviousRenewalTokenExpiresAt string

	TLSCAFile     string
	TLSCertFile   string
	TLSKeyFile    string
	TLSServerName string

	ControlHeartbeatEvery     time.Duration
	ControlHeartbeatJitter    time.Duration
	ControlConfigEvery        time.Duration
	ControlConfigJitter       time.Duration
	ControlResponsePollEvery  time.Duration
	ControlResponsePollJitter time.Duration
	ControlEnrollTimeout      time.Duration
	ForceEnrollOnStart        bool
	CredentialRotateEvery     time.Duration
	CredentialRotateBefore    time.Duration
	CertRotateEvery           time.Duration
	CertRotateBefore          time.Duration
	ResponseActionStageMax    int

	SyscollectEvery          time.Duration
	SyscollectStartupJitter  time.Duration
	SyscollectCmdTimeout     time.Duration
	SyscollectMaxOutputBytes int64
	SyscollectMaxPackages    int
	SyscollectHostRoot       string

	VulnScanEvery        time.Duration
	VulnStartupJitter    time.Duration
	VulnOSVURL           string
	VulnMinSeverity      string
	VulnAnalysisProfile  string
	VulnExposureEnabled  bool
	VulnQueryBatchSize   int
	VulnCmdTimeout       time.Duration
	VulnHTTPTimeout      time.Duration
	VulnMaxOutputBytes   int64
	VulnMaxPackages      int
	VulnHostRoot         string
	VulnEmitSummaryEvent bool

	AuthLogPath         string
	AuthIncludeAccepted bool
	AuthDedupTTL        time.Duration

	ProcTCP4Path string
	ProcTCP6Path string

	ProcExecEvery             time.Duration
	ProcExecMaxBatch          int
	ProcExecHashEnabled       bool
	ProcExecHashMaxBytes      int64
	ProcExecEmitInitial       bool
	ProcExecIgnoreExeNames    map[string]bool
	ProcExecIgnoreCmdContains []string

	FIMEvery        time.Duration
	FIMMaxBatch     int
	FIMMaxDepth     int
	FIMHashEnabled  bool
	FIMHashMaxBytes int64
	FIMEmitInitial  bool
	FIMWatchPaths   []string
	FIMExcludePaths []string

	L7Iface           string
	L7DedupTTL        time.Duration
	L7MaxBatch        int
	L7MaxPayloadBytes int
	L7IncludePayload  bool

	SkipLoopback         bool
	SkipLinkLocal        bool
	SkipPrivateToPrivate bool

	ProcDropLikelyOutbound bool
	EphemeralPortMin       int

	DedupTTL       time.Duration
	EstablishedTTL time.Duration

	DenyCIDRs    []*net.IPNet
	DenyDstPorts map[int]bool
	DenySrcPorts map[int]bool

	LateralMode               string
	LateralIface              string
	LateralPorts              map[int]bool
	LateralIncludeEstablished bool
	LateralDedupTTL           time.Duration
	LateralMaxBatch           int

	ScanIface    string
	ScanDedupTTL time.Duration
	ScanMaxBatch int

	ScanMode string

	DDoSIface                   string
	DDoSWindow                  time.Duration
	DDoSEvalEvery               time.Duration
	DDoSCooldown                time.Duration
	DDoSSustainWindows          int
	DDoSBaselineWarmupWindows   int
	DDoSBaselineAlpha           float64
	DDoSBaselineFactor          float64
	DDoSMinPPS                  float64
	DDoSMinBPS                  float64
	DDoSMinPackets              int
	DDoSMinRequests             int
	DDoSMinConfidence           int
	DDoSMinSynRatio             float64
	DDoSMinSrcIPs               int
	DDoSMinSrcEntropyNorm       float64
	DDoSEnableL7                bool
	DDoSMinHTTPRPS              float64
	DDoSMinTLSHSRPS             float64
	DDoSMinL7Ratio              float64
	DDoSEnableEntropy           bool
	DDoSMinSrcEntropyNormSignal float64
	DDoSMinPortEntropyNorm      float64
	DDoSPortEntropyTopN         int
	DDoSCardinalityMode         string
	DDoSHLLPrecision            int
	DDoSBloomBits               int
	DDoSMaxUniqueSrc            int
	DDoSTopSrc                  int
	DDoSMaxBatch                int
	DDoSBackpressureHighWM      int
	DDoSBackpressureSampleEvery int

	NetCtxMaxInterfaces int
	NetCtxMaxNeighbors  int
	NetCtxMaxRoutes     int
	NetCtxMaxResolvers  int

	TopologyActiveDiscoveryEnabled     bool
	TopologyActiveDiscoveryCIDRs       []*net.IPNet
	TopologyActiveDiscoveryAllowPublic bool
	TopologyActiveDiscoveryInterval    time.Duration
	TopologyActiveDiscoveryMaxHosts    int
	TopologyActiveDiscoveryRateLimit   int
	TopologyActiveDiscoveryTimeout     time.Duration

	LogLevel          LogLevel
	LogSummaryEvery   time.Duration
	LogHeartbeatEvery time.Duration
	LogMinEvents      int
}

func LoadConfig() Config {
	agentID := getEnv("SEAGULL_AGENT_ID", "agent-unknown")
	apiURL := strings.TrimSpace(getEnv("SEAGULL_API_URL", ""))
	if apiURL == "" {
		log.Fatal("[AGENT] SEAGULL_API_URL is required")
	}
	sources := splitCSVLower(getEnv("SEAGULL_SOURCES", defaultL7Sources))

	interval := parseDuration(getEnv("SEAGULL_POLL_INTERVAL", "1s"), 1*time.Second)
	httpTimeout := parseDuration(getEnv("SEAGULL_HTTP_TIMEOUT", "10s"), 10*time.Second)
	senderMaxBatch := parseInt(getEnv("SEAGULL_SENDER_MAX_BATCH", "300"), 300)

	agentConfigFile := getEnv("SEAGULL_AGENT_CONFIG_FILE", "/var/lib/seagull/agent.config.json")
	agentIdentityStateFile := getEnv("SEAGULL_AGENT_IDENTITY_STATE_FILE", "/var/lib/seagull/agent.identity.json")
	credentialFile := strings.TrimSpace(getEnv("SEAGULL_AGENT_CREDENTIAL_FILE", "/var/lib/seagull/agent.credential"))
	agentCredential := strings.TrimSpace(getSecretEnv("SEAGULL_AGENT_CREDENTIAL", ""))
	agentCredentialExpiresAt := ""
	renewalToken := ""
	renewalTokenExpiresAt := ""
	previousRenewalToken := ""
	previousRenewalTokenExpiresAt := ""

	if state, err := LoadIdentityState(agentIdentityStateFile, agentID); err != nil {
		LogJSON(LevelWarn, "identity_state_load_failed", map[string]interface{}{
			"agent_id": agentID,
			"path":     agentIdentityStateFile,
			"error":    err.Error(),
		})
	} else {
		if agentCredential == "" {
			agentCredential = strings.TrimSpace(state.Credential)
		}
		if agentCredentialExpiresAt == "" {
			agentCredentialExpiresAt = strings.TrimSpace(state.CredentialExpiresAt)
		}
		renewalToken = strings.TrimSpace(state.RenewalToken)
		renewalTokenExpiresAt = strings.TrimSpace(state.RenewalTokenExpiresAt)
		previousRenewalToken = strings.TrimSpace(state.PreviousRenewalToken)
		previousRenewalTokenExpiresAt = strings.TrimSpace(state.PreviousRenewalTokenExpiresAt)
	}

	if agentCredential == "" && credentialFile != "" {
		agentCredential = strings.TrimSpace(ReadTextFile(credentialFile))
	}
	hasExistingIdentity := agentCredential != "" || renewalToken != "" || previousRenewalToken != ""
	bootstrapToken, bootstrapTokenFile, err := LoadBootstrapTokenValue(hasExistingIdentity)
	if err != nil {
		log.Fatalf("[AGENT] bootstrap token config error: %v", err)
	}

	tlsCAFile := strings.TrimSpace(getEnv("SEAGULL_TLS_CA_FILE", ""))
	tlsCertFile := strings.TrimSpace(getEnv("SEAGULL_TLS_CERT_FILE", ""))
	tlsKeyFile := strings.TrimSpace(getEnv("SEAGULL_TLS_KEY_FILE", ""))
	tlsServerName := strings.TrimSpace(getEnv("SEAGULL_TLS_SERVER_NAME", ""))
	if (tlsCertFile == "") != (tlsKeyFile == "") {
		log.Fatal("[AGENT] SEAGULL_TLS_CERT_FILE and SEAGULL_TLS_KEY_FILE must be set together")
	}

	controlHeartbeatEvery := parseDuration(getEnv("SEAGULL_CONTROL_HEARTBEAT_EVERY", "30s"), 30*time.Second)
	controlHeartbeatJitter := parseDuration(getEnv("SEAGULL_CONTROL_HEARTBEAT_JITTER", "5s"), 5*time.Second)
	controlConfigEvery := parseDuration(getEnv("SEAGULL_CONTROL_CONFIG_EVERY", "5m"), 5*time.Minute)
	controlConfigJitter := parseDuration(getEnv("SEAGULL_CONTROL_CONFIG_JITTER", "30s"), 30*time.Second)
	controlResponsePollEvery := parseDuration(getEnv("SEAGULL_CONTROL_RESPONSE_ACTIONS_POLL_EVERY", "15s"), 15*time.Second)
	controlResponsePollJitter := parseDuration(getEnv("SEAGULL_CONTROL_RESPONSE_ACTIONS_POLL_JITTER", "5s"), 5*time.Second)
	controlEnrollTimeout := parseDuration(getEnv("SEAGULL_CONTROL_ENROLL_TIMEOUT", "10s"), 10*time.Second)
	forceEnrollOnStart := parseBool(getEnv("SEAGULL_FORCE_ENROLL_ON_START", "true"), true)
	credentialRotateEvery := parseDuration(getEnv("SEAGULL_CONTROL_CREDENTIAL_ROTATE_EVERY", "5m"), 5*time.Minute)
	credentialRotateBefore := parseDuration(getEnv("SEAGULL_CONTROL_CREDENTIAL_ROTATE_BEFORE", "24h"), 24*time.Hour)
	certRotateEvery := parseDuration(getEnv("SEAGULL_CONTROL_CERT_ROTATE_EVERY", "1h"), time.Hour)
	certRotateBefore := parseDuration(getEnv("SEAGULL_CONTROL_CERT_ROTATE_BEFORE", "720h"), 720*time.Hour)
	responseActionStageMax := parseInt(getEnv("SEAGULL_RESPONSE_ACTION_STAGE_MAX", "512"), 512)

	syscollectEvery := parseDuration(getEnv("SEAGULL_SYSCOLLECT_EVERY", "5m"), 5*time.Minute)
	syscollectStartupJitter := parseDuration(getEnv("SEAGULL_SYSCOLLECT_STARTUP_JITTER", "45s"), 45*time.Second)
	syscollectCmdTimeout := parseDuration(getEnv("SEAGULL_SYSCOLLECT_CMD_TIMEOUT", "10s"), 10*time.Second)
	syscollectMaxOutputBytes := int64(parseInt(getEnv("SEAGULL_SYSCOLLECT_MAX_OUTPUT_BYTES", "8388608"), 8388608))
	syscollectMaxPackages := parseInt(getEnv("SEAGULL_SYSCOLLECT_MAX_PACKAGES", "50000"), 50000)
	syscollectHostRoot := strings.TrimSpace(getEnv("SEAGULL_HOST_ROOT", ""))

	vulnEvery := parseDuration(getEnv("SEAGULL_VULN_SCAN_EVERY", "12h"), 12*time.Hour)
	vulnStartupJitter := parseDuration(getEnv("SEAGULL_VULN_STARTUP_JITTER", "2m"), 2*time.Minute)
	vulnOSVURL := strings.TrimSpace(getEnv("SEAGULL_VULN_OSV_URL", "https://api.osv.dev"))
	vulnMinSeverity := strings.ToLower(strings.TrimSpace(getEnv("SEAGULL_VULN_MIN_SEVERITY", "medium")))
	vulnAnalysisProfile := strings.TrimSpace(getEnv("SEAGULL_VULN_ANALYSIS_PROFILE", "wazuh_like_v1"))
	vulnExposureEnabled := parseBool(getEnv("SEAGULL_VULN_EXPOSURE_ENABLED", "true"), true)
	vulnBatch := parseInt(getEnv("SEAGULL_VULN_QUERY_BATCH_SIZE", "200"), 200)
	vulnCmdTimeout := parseDuration(getEnv("SEAGULL_VULN_CMD_TIMEOUT", "15s"), 15*time.Second)
	vulnHTTPTimeout := parseDuration(getEnv("SEAGULL_VULN_HTTP_TIMEOUT", "60s"), 60*time.Second)
	vulnMaxOutputBytes := int64(parseInt(getEnv("SEAGULL_VULN_MAX_OUTPUT_BYTES", "8388608"), 8388608))
	vulnMaxPackages := parseInt(getEnv("SEAGULL_VULN_MAX_PACKAGES", strconv.Itoa(syscollectMaxPackages)), syscollectMaxPackages)
	vulnHostRoot := strings.TrimSpace(getEnv("SEAGULL_VULN_HOST_ROOT", syscollectHostRoot))
	vulnEmitSummaryEvent := parseBool(getEnv("SEAGULL_VULN_EMIT_SUMMARY_EVENT", "true"), true)

	logPath := getEnv("SEAGULL_AUTHLOG_PATH", "/var/log/auth.log")
	includeAccepted := parseBool(getEnv("SEAGULL_AUTHLOG_INCLUDE_ACCEPTED", "false"), false)
	authDedupTTL := parseDuration(getEnv("SEAGULL_AUTHLOG_DEDUP_TTL", "30s"), 30*time.Second)

	procTCP4Path := getEnv("SEAGULL_PROC_TCP4_PATH", "/proc/net/tcp")
	procTCP6Path := getEnv("SEAGULL_PROC_TCP6_PATH", "/proc/net/tcp6")
	procExecEvery := parseDuration(getEnv("SEAGULL_PROC_EXEC_EVERY", "2s"), 2*time.Second)
	procExecMaxBatch := parseInt(getEnv("SEAGULL_PROC_EXEC_MAX_BATCH", "200"), 200)
	procExecHashEnabled := parseBool(getEnv("SEAGULL_PROC_EXEC_HASH_ENABLED", "true"), true)
	procExecHashMaxBytes := int64(parseInt(getEnv("SEAGULL_PROC_EXEC_HASH_MAX_BYTES", "26214400"), 26214400))
	procExecEmitInitial := parseBool(getEnv("SEAGULL_PROC_EXEC_EMIT_INITIAL", "false"), false)
	procExecIgnoreExeNames := parseStringSet(getEnv("SEAGULL_PROC_EXEC_IGNORE_EXE", "sleep"))
	procExecIgnoreCmdContains := splitCSVLower(getEnv("SEAGULL_PROC_EXEC_IGNORE_CMD_CONTAINS", "systemd --user"))

	fimEvery := parseDuration(getEnv("SEAGULL_FIM_EVERY", "30s"), 30*time.Second)
	fimMaxBatch := parseInt(getEnv("SEAGULL_FIM_MAX_BATCH", "200"), 200)
	fimMaxDepth := parseInt(getEnv("SEAGULL_FIM_MAX_DEPTH", "4"), 4)
	fimHashEnabled := parseBool(getEnv("SEAGULL_FIM_HASH_ENABLED", "true"), true)
	fimHashMaxBytes := int64(parseInt(getEnv("SEAGULL_FIM_HASH_MAX_BYTES", "2097152"), 2097152))
	fimEmitInitial := parseBool(getEnv("SEAGULL_FIM_EMIT_INITIAL", "false"), false)
	fimWatchPaths := splitCSV(getEnv("SEAGULL_FIM_PATHS", ""))
	fimExclude := splitCSV(getEnv("SEAGULL_FIM_EXCLUDE_PATHS", ""))

	skipLoopback := parseBool(getEnv("SEAGULL_SKIP_LOOPBACK", "true"), true)
	skipLinkLocal := parseBool(getEnv("SEAGULL_SKIP_LINK_LOCAL", "true"), true)
	skipPrivate := parseBool(getEnv("SEAGULL_SKIP_PRIVATE_TO_PRIVATE", "false"), false)

	procDropOutbound := parseBool(getEnv("SEAGULL_PROC_DROP_LIKELY_OUTBOUND", "true"), true)
	ephemeralMin := parseInt(getEnv("SEAGULL_EPHEMERAL_PORT_MIN", "49152"), 49152)

	dedupTTL := parseDuration(getEnv("SEAGULL_DEDUP_TTL", "30s"), 30*time.Second)
	establishedTTL := parseDuration(getEnv("SEAGULL_ESTABLISHED_TTL", "10m"), 10*time.Minute)

	denyCIDRs := parseCIDRs(getEnv("SEAGULL_DENY_CIDRS", ""))
	denyDstPorts := parseIntSet(getEnv("SEAGULL_DENY_DST_PORTS", ""))
	denySrcPorts := parseIntSet(getEnv("SEAGULL_DENY_SRC_PORTS", ""))

	lateralMode := strings.ToLower(strings.TrimSpace(getEnv("SEAGULL_LATERAL_MODE", "pcap")))
	lateralIface := getEnv("SEAGULL_LATERAL_PCAP_IFACE", getEnv("SEAGULL_PCAP_IFACE", "any"))
	lateralPorts := parseIntSet(getEnv("SEAGULL_LATERAL_PORTS", "22,445,3389,5985,5986,135,139"))
	lateralIncludeEstablished := parseBool(getEnv("SEAGULL_LATERAL_INCLUDE_ESTABLISHED", "true"), true)
	lateralDedup := parseDuration(getEnv("SEAGULL_LATERAL_DEDUP_TTL", "5s"), 5*time.Second)
	lateralMaxBatch := parseInt(getEnv("SEAGULL_LATERAL_MAX_BATCH", "500"), 500)

	scanIface := getEnv("SEAGULL_PCAP_IFACE", "any")
	scanDedup := parseDuration(getEnv("SEAGULL_SCAN_DEDUP_TTL", "2s"), 2*time.Second)
	scanMaxBatch := parseInt(getEnv("SEAGULL_SCAN_MAX_BATCH", "5000"), 5000)
	scanMode := getEnv("SEAGULL_SCAN_MODE", "summary")
	l7Iface := getEnvAlias("SEAGULL_L7_PCAP_IFACE", scanIface, "SEAGULL_L7_IFACE")
	l7Dedup := parseDuration(getEnvAlias("SEAGULL_L7_DEDUP_TTL", DefaultL7DedupTTL.String()), DefaultL7DedupTTL)
	l7MaxBatch := parseInt(getEnvAlias("SEAGULL_L7_MAX_BATCH", strconv.Itoa(DefaultL7MaxBatch), "SEAGULL_L7_BATCH_SIZE"), DefaultL7MaxBatch)
	l7MaxPayload := parseInt(getEnvAlias("SEAGULL_L7_MAX_PAYLOAD_BYTES", strconv.Itoa(DefaultL7MaxPayloadBytes), "SEAGULL_L7_PAYLOAD_BYTES"), DefaultL7MaxPayloadBytes)
	l7IncludePayload := parseBool(getEnvAlias("SEAGULL_L7_INCLUDE_PAYLOAD", "false"), false)

	ddosIface := getEnv("SEAGULL_DDOS_PCAP_IFACE", scanIface)
	ddosWindow := parseDuration(getEnv("SEAGULL_DDOS_WINDOW", "1s"), 1*time.Second)
	ddosEvalEvery := parseDuration(getEnv("SEAGULL_DDOS_EVAL_EVERY", "1s"), 1*time.Second)
	ddosCooldown := parseDuration(getEnv("SEAGULL_DDOS_COOLDOWN", "30s"), 30*time.Second)
	ddosSustain := parseInt(getEnv("SEAGULL_DDOS_SUSTAIN_WINDOWS", "3"), 3)
	ddosWarmup := parseInt(getEnv("SEAGULL_DDOS_BASELINE_WARMUP_WINDOWS", "20"), 20)
	ddosAlpha := parseFloat(getEnv("SEAGULL_DDOS_BASELINE_ALPHA", "0.08"), 0.08)
	ddosFactor := parseFloat(getEnv("SEAGULL_DDOS_BASELINE_FACTOR", "4.0"), 4.0)
	ddosMinPPS := parseFloat(getEnv("SEAGULL_DDOS_MIN_PPS", "3000"), 3000)
	ddosMinBPS := parseFloat(getEnv("SEAGULL_DDOS_MIN_BPS", "500000"), 500000)
	ddosMinPackets := parseInt(getEnv("SEAGULL_DDOS_MIN_PACKETS", "0"), 0)
	ddosMinRequests := parseInt(getEnv("SEAGULL_DDOS_MIN_REQUESTS", "0"), 0)
	ddosMinConf := parseInt(getEnv("SEAGULL_DDOS_MIN_CONFIDENCE", "70"), 70)
	ddosMinSynRatio := parseFloat(getEnv("SEAGULL_DDOS_MIN_SYN_RATIO", "0.70"), 0.70)
	ddosMinSrcIPs := parseInt(getEnv("SEAGULL_DDOS_MIN_SRC_IPS", "30"), 30)
	ddosMinSrcEntropy := parseFloat(getEnv("SEAGULL_DDOS_MIN_SRC_ENTROPY_NORM", "0.70"), 0.70)

	ddosEnableL7 := parseBool(getEnv("SEAGULL_DDOS_ENABLE_L7", "true"), true)
	ddosMinHTTPRPS := parseFloat(getEnv("SEAGULL_DDOS_MIN_HTTP_RPS", "200"), 200)
	ddosMinTLS := parseFloat(getEnv("SEAGULL_DDOS_MIN_TLS_HS_RPS", "200"), 200)
	ddosMinL7Ratio := parseFloat(getEnv("SEAGULL_DDOS_MIN_L7_RATIO", "0.15"), 0.15)

	ddosEnableEntropy := parseBool(getEnv("SEAGULL_DDOS_ENABLE_ENTROPY", "true"), true)
	ddosMinSrcEntropySig := parseFloat(getEnv("SEAGULL_DDOS_MIN_SRC_ENTROPY_NORM_SIGNAL", "0.75"), 0.75)
	ddosMinPortEntropy := parseFloat(getEnv("SEAGULL_DDOS_MIN_PORT_ENTROPY_NORM", "0.35"), 0.35)
	ddosPortTopN := parseInt(getEnv("SEAGULL_DDOS_PORT_ENTROPY_TOPN", "16"), 16)

	ddosCardMode := strings.ToLower(strings.TrimSpace(getEnv("SEAGULL_DDOS_CARDINALITY_MODE", "hll")))
	ddosHLLP := parseInt(getEnv("SEAGULL_DDOS_HLL_PRECISION", "14"), 14)
	ddosBloomBits := parseInt(getEnv("SEAGULL_DDOS_BLOOM_BITS", "1048576"), 1048576)
	ddosMaxUnique := parseInt(getEnv("SEAGULL_DDOS_MAX_UNIQUE_SRC", "500000"), 500000)
	ddosTopSrc := parseInt(getEnv("SEAGULL_DDOS_TOP_SRC", "20"), 20)
	ddosMaxBatch := parseInt(getEnv("SEAGULL_DDOS_MAX_BATCH", "200"), 200)
	ddosBpHighWM := parseInt(getEnv("SEAGULL_DDOS_BACKPRESSURE_HIGH_WATERMARK", "160"), 160)
	ddosBpSampleEvery := parseInt(getEnv("SEAGULL_DDOS_BACKPRESSURE_SAMPLE_EVERY", "4"), 4)

	netCtxMaxIfaces := parseInt(getEnv("SEAGULL_NETCTX_MAX_INTERFACES", "64"), 64)
	netCtxMaxNeighbors := parseInt(getEnv("SEAGULL_NETCTX_MAX_NEIGHBORS", "512"), 512)
	netCtxMaxRoutes := parseInt(getEnv("SEAGULL_NETCTX_MAX_ROUTES", "256"), 256)
	netCtxMaxResolvers := parseInt(getEnv("SEAGULL_NETCTX_MAX_RESOLVERS", "8"), 8)

	topologyActiveDiscoveryEnabled := parseBool(getEnv("SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_ENABLED", "false"), false)
	topologyActiveDiscoveryAllowPublic := parseBool(getEnv("SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_ALLOW_PUBLIC", "false"), false)
	topologyActiveDiscoveryCIDRs, err := ValidateActiveDiscoveryCIDRs(
		getEnv("SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_CIDRS", ""),
		topologyActiveDiscoveryAllowPublic,
	)
	if err != nil {
		log.Fatalf("[AGENT] topology active discovery config error: %v", err)
	}
	topologyActiveDiscoveryInterval := parseDuration(
		getEnv("SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_INTERVAL", "30m"),
		30*time.Minute,
	)
	topologyActiveDiscoveryMaxHosts := clampInt(
		parseInt(getEnv("SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_MAX_HOSTS", "256"), 256),
		1,
		4096,
	)
	topologyActiveDiscoveryRateLimit := clampInt(
		parseInt(getEnv("SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_RATE_LIMIT", "20"), 20),
		1,
		512,
	)
	topologyActiveDiscoveryTimeout := parseDuration(
		getEnv("SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_TIMEOUT", "30s"),
		30*time.Second,
	)

	levelStr := getEnv("SEAGULL_LOG_LEVEL", "info")
	logLevel := ParseLogLevel(levelStr)

	logSummaryEvery := parseDuration(getEnv("SEAGULL_LOG_SUMMARY_EVERY", "10s"), 10*time.Second)
	logHeartbeatEvery := parseDuration(getEnv("SEAGULL_LOG_HEARTBEAT_EVERY", "60s"), 60*time.Second)
	logMinEvents := parseInt(getEnv("SEAGULL_LOG_MIN_EVENTS", "50"), 50)

	cfg := Config{
		AgentID:        agentID,
		APIURL:         apiURL,
		Sources:        sources,
		Interval:       interval,
		HTTPTimeout:    httpTimeout,
		SenderMaxBatch: senderMaxBatch,

		AgentConfigFile:               agentConfigFile,
		AgentIdentityStateFile:        agentIdentityStateFile,
		BootstrapToken:                bootstrapToken,
		BootstrapTokenFile:            bootstrapTokenFile,
		AgentCredential:               agentCredential,
		AgentCredentialExpiresAt:      agentCredentialExpiresAt,
		CredentialFile:                credentialFile,
		RenewalToken:                  renewalToken,
		RenewalTokenExpiresAt:         renewalTokenExpiresAt,
		PreviousRenewalToken:          previousRenewalToken,
		PreviousRenewalTokenExpiresAt: previousRenewalTokenExpiresAt,

		TLSCAFile:     tlsCAFile,
		TLSCertFile:   tlsCertFile,
		TLSKeyFile:    tlsKeyFile,
		TLSServerName: tlsServerName,

		ControlHeartbeatEvery:     controlHeartbeatEvery,
		ControlHeartbeatJitter:    controlHeartbeatJitter,
		ControlConfigEvery:        controlConfigEvery,
		ControlConfigJitter:       controlConfigJitter,
		ControlResponsePollEvery:  controlResponsePollEvery,
		ControlResponsePollJitter: controlResponsePollJitter,
		ControlEnrollTimeout:      controlEnrollTimeout,
		ForceEnrollOnStart:        forceEnrollOnStart,
		CredentialRotateEvery:     credentialRotateEvery,
		CredentialRotateBefore:    credentialRotateBefore,
		CertRotateEvery:           certRotateEvery,
		CertRotateBefore:          certRotateBefore,
		ResponseActionStageMax:    responseActionStageMax,

		SyscollectEvery:          syscollectEvery,
		SyscollectStartupJitter:  syscollectStartupJitter,
		SyscollectCmdTimeout:     syscollectCmdTimeout,
		SyscollectMaxOutputBytes: syscollectMaxOutputBytes,
		SyscollectMaxPackages:    syscollectMaxPackages,
		SyscollectHostRoot:       syscollectHostRoot,

		VulnScanEvery:        vulnEvery,
		VulnStartupJitter:    vulnStartupJitter,
		VulnOSVURL:           vulnOSVURL,
		VulnMinSeverity:      vulnMinSeverity,
		VulnAnalysisProfile:  vulnAnalysisProfile,
		VulnExposureEnabled:  vulnExposureEnabled,
		VulnQueryBatchSize:   vulnBatch,
		VulnCmdTimeout:       vulnCmdTimeout,
		VulnHTTPTimeout:      vulnHTTPTimeout,
		VulnMaxOutputBytes:   vulnMaxOutputBytes,
		VulnMaxPackages:      vulnMaxPackages,
		VulnHostRoot:         vulnHostRoot,
		VulnEmitSummaryEvent: vulnEmitSummaryEvent,

		AuthLogPath:         logPath,
		AuthIncludeAccepted: includeAccepted,
		AuthDedupTTL:        authDedupTTL,

		ProcTCP4Path: procTCP4Path,
		ProcTCP6Path: procTCP6Path,

		ProcExecEvery:             procExecEvery,
		ProcExecMaxBatch:          procExecMaxBatch,
		ProcExecHashEnabled:       procExecHashEnabled,
		ProcExecHashMaxBytes:      procExecHashMaxBytes,
		ProcExecEmitInitial:       procExecEmitInitial,
		ProcExecIgnoreExeNames:    procExecIgnoreExeNames,
		ProcExecIgnoreCmdContains: procExecIgnoreCmdContains,

		FIMEvery:        fimEvery,
		FIMMaxBatch:     fimMaxBatch,
		FIMMaxDepth:     fimMaxDepth,
		FIMHashEnabled:  fimHashEnabled,
		FIMHashMaxBytes: fimHashMaxBytes,
		FIMEmitInitial:  fimEmitInitial,
		FIMWatchPaths:   fimWatchPaths,
		FIMExcludePaths: fimExclude,

		L7Iface:           l7Iface,
		L7DedupTTL:        l7Dedup,
		L7MaxBatch:        l7MaxBatch,
		L7MaxPayloadBytes: l7MaxPayload,
		L7IncludePayload:  l7IncludePayload,

		SkipLoopback:         skipLoopback,
		SkipLinkLocal:        skipLinkLocal,
		SkipPrivateToPrivate: skipPrivate,

		ProcDropLikelyOutbound: procDropOutbound,
		EphemeralPortMin:       ephemeralMin,

		DedupTTL:       dedupTTL,
		EstablishedTTL: establishedTTL,

		DenyCIDRs:    denyCIDRs,
		DenyDstPorts: denyDstPorts,
		DenySrcPorts: denySrcPorts,

		LateralMode:               lateralMode,
		LateralIface:              lateralIface,
		LateralPorts:              lateralPorts,
		LateralIncludeEstablished: lateralIncludeEstablished,
		LateralDedupTTL:           lateralDedup,
		LateralMaxBatch:           lateralMaxBatch,

		ScanIface:    scanIface,
		ScanDedupTTL: scanDedup,
		ScanMaxBatch: scanMaxBatch,

		ScanMode: scanMode,

		DDoSIface:                   ddosIface,
		DDoSWindow:                  ddosWindow,
		DDoSEvalEvery:               ddosEvalEvery,
		DDoSCooldown:                ddosCooldown,
		DDoSSustainWindows:          ddosSustain,
		DDoSBaselineWarmupWindows:   ddosWarmup,
		DDoSBaselineAlpha:           ddosAlpha,
		DDoSBaselineFactor:          ddosFactor,
		DDoSMinPPS:                  ddosMinPPS,
		DDoSMinBPS:                  ddosMinBPS,
		DDoSMinPackets:              ddosMinPackets,
		DDoSMinRequests:             ddosMinRequests,
		DDoSMinConfidence:           ddosMinConf,
		DDoSMinSynRatio:             ddosMinSynRatio,
		DDoSMinSrcIPs:               ddosMinSrcIPs,
		DDoSMinSrcEntropyNorm:       ddosMinSrcEntropy,
		DDoSEnableL7:                ddosEnableL7,
		DDoSMinHTTPRPS:              ddosMinHTTPRPS,
		DDoSMinTLSHSRPS:             ddosMinTLS,
		DDoSMinL7Ratio:              ddosMinL7Ratio,
		DDoSEnableEntropy:           ddosEnableEntropy,
		DDoSMinSrcEntropyNormSignal: ddosMinSrcEntropySig,
		DDoSMinPortEntropyNorm:      ddosMinPortEntropy,
		DDoSPortEntropyTopN:         ddosPortTopN,
		DDoSCardinalityMode:         ddosCardMode,
		DDoSHLLPrecision:            ddosHLLP,
		DDoSBloomBits:               ddosBloomBits,
		DDoSMaxUniqueSrc:            ddosMaxUnique,
		DDoSTopSrc:                  ddosTopSrc,
		DDoSMaxBatch:                ddosMaxBatch,
		DDoSBackpressureHighWM:      ddosBpHighWM,
		DDoSBackpressureSampleEvery: ddosBpSampleEvery,

		NetCtxMaxInterfaces: netCtxMaxIfaces,
		NetCtxMaxNeighbors:  netCtxMaxNeighbors,
		NetCtxMaxRoutes:     netCtxMaxRoutes,
		NetCtxMaxResolvers:  netCtxMaxResolvers,

		TopologyActiveDiscoveryEnabled:     topologyActiveDiscoveryEnabled,
		TopologyActiveDiscoveryCIDRs:       topologyActiveDiscoveryCIDRs,
		TopologyActiveDiscoveryAllowPublic: topologyActiveDiscoveryAllowPublic,
		TopologyActiveDiscoveryInterval:    topologyActiveDiscoveryInterval,
		TopologyActiveDiscoveryMaxHosts:    topologyActiveDiscoveryMaxHosts,
		TopologyActiveDiscoveryRateLimit:   topologyActiveDiscoveryRateLimit,
		TopologyActiveDiscoveryTimeout:     topologyActiveDiscoveryTimeout,

		LogLevel:          logLevel,
		LogSummaryEvery:   logSummaryEvery,
		LogHeartbeatEvery: logHeartbeatEvery,
		LogMinEvents:      logMinEvents,
	}
	sanitizeL7Config(&cfg)
	return cfg
}

func LoadBootstrapTokenValue(hasExistingIdentity bool) (string, string, error) {
	token := strings.TrimSpace(getSecretEnv("SEAGULL_AGENT_BOOTSTRAP_TOKEN", ""))
	tokenFile := strings.TrimSpace(getEnv("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE", ""))
	if tokenFile == "" {
		return token, "", nil
	}

	data, err := os.ReadFile(tokenFile)
	if err != nil {
		if hasExistingIdentity && os.IsNotExist(err) {
			return token, tokenFile, nil
		}
		return "", tokenFile, fmt.Errorf("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE=%q: %w", tokenFile, err)
	}
	fileToken := strings.TrimSpace(string(data))
	if fileToken == "" {
		if hasExistingIdentity {
			return token, tokenFile, nil
		}
		return "", tokenFile, fmt.Errorf("SEAGULL_AGENT_BOOTSTRAP_TOKEN_FILE=%q: file is empty", tokenFile)
	}
	return fileToken, tokenFile, nil
}

func ConsumeBootstrapTokenFile(path string, agentID string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if errors.Is(err, syscall.EROFS) || os.IsPermission(err) {
			LogJSON(LevelInfo, "agent_bootstrap_token_file_preserved", map[string]interface{}{
				"agent_id": agentID,
				"path":     path,
				"reason":   "externally_managed_or_read_only",
			})
			return
		}
		LogJSON(LevelWarn, "agent_bootstrap_token_file_delete_failed", map[string]interface{}{
			"agent_id": agentID,
			"path":     path,
			"error":    err.Error(),
		})
		return
	}
	LogJSON(LevelInfo, "agent_bootstrap_token_file_deleted", map[string]interface{}{
		"agent_id": agentID,
		"path":     path,
	})
}

func NormalizeScanMode(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "raw", "both", "summary":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "summary"
	}
}

func Contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func getEnv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return v
	}
	if strings.HasPrefix(k, "SEAGULL_") {
		legacyKey := "NETWATCH_" + strings.TrimPrefix(k, "SEAGULL_")
		if v, ok := os.LookupEnv(legacyKey); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return def
}

func getEnvAlias(k, def string, aliases ...string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if strings.HasPrefix(k, "SEAGULL_") {
		legacyKey := "NETWATCH_" + strings.TrimPrefix(k, "SEAGULL_")
		if v, ok := os.LookupEnv(legacyKey); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	for _, alias := range aliases {
		if v := getEnv(alias, ""); strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return def
}

func getSecretEnv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}

	if filePath, ok := os.LookupEnv(k + "_FILE"); ok && strings.TrimSpace(filePath) != "" {
		return ReadTextFile(filePath)
	}

	if strings.HasPrefix(k, "SEAGULL_") {
		legacyKey := "NETWATCH_" + strings.TrimPrefix(k, "SEAGULL_")
		if v, ok := os.LookupEnv(legacyKey); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		if filePath, ok := os.LookupEnv(legacyKey + "_FILE"); ok && strings.TrimSpace(filePath) != "" {
			return ReadTextFile(filePath)
		}
	}

	return def
}

func parseDuration(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d <= 0 {
		return def
	}
	return d
}

func parseInt(s string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func parseFloat(s string, def float64) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func parseBool(s string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

func clampInt(v, minValue, maxValue int) int {
	if v < minValue {
		return minValue
	}
	if v > maxValue {
		return maxValue
	}
	return v
}

func sanitizeL7Config(cfg *Config) {
	if cfg == nil {
		return
	}
	if strings.TrimSpace(cfg.L7Iface) == "" {
		cfg.L7Iface = "any"
	}
	if cfg.L7DedupTTL <= 0 {
		cfg.L7DedupTTL = DefaultL7DedupTTL
	}
	cfg.L7MaxBatch = clampInt(cfg.L7MaxBatch, 1, MaxL7MaxBatch)
	cfg.L7MaxPayloadBytes = clampInt(cfg.L7MaxPayloadBytes, 1, MaxL7MaxPayloadBytes)
}

func parseCIDRs(csv string) []*net.IPNet {
	parts := strings.Split(csv, ",")
	out := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, n, err := net.ParseCIDR(p)
		if err == nil && n != nil {
			out = append(out, n)
		}
	}
	return out
}

func ParseStrictCIDRs(csv string) ([]*net.IPNet, error) {
	parts := strings.Split(csv, ",")
	out := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		raw := strings.TrimSpace(p)
		if raw == "" {
			continue
		}
		ip, n, err := net.ParseCIDR(raw)
		if err != nil || n == nil || ip == nil {
			return nil, fmt.Errorf("invalid CIDR %q", raw)
		}
		n.IP = ip.Mask(n.Mask)
		out = append(out, n)
	}
	return out, nil
}

func ValidateActiveDiscoveryCIDRs(csv string, allowPublic bool) ([]*net.IPNet, error) {
	cidrs, err := ParseStrictCIDRs(csv)
	if err != nil {
		return nil, err
	}
	for _, cidr := range cidrs {
		if cidr == nil {
			continue
		}
		if !allowPublic && !isPrivateOrInternalCIDR(cidr) {
			return nil, fmt.Errorf("public CIDR %q requires SEAGULL_TOPOLOGY_ACTIVE_DISCOVERY_ALLOW_PUBLIC=true", cidr.String())
		}
	}
	return cidrs, nil
}

func CIDRStrings(cidrs []*net.IPNet) []string {
	out := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		if cidr == nil {
			continue
		}
		out = append(out, cidr.String())
	}
	return out
}

func isPrivateOrInternalCIDR(cidr *net.IPNet) bool {
	if cidr == nil || cidr.IP == nil {
		return false
	}
	for _, raw := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
		"::1/128",
	} {
		_, parent, err := net.ParseCIDR(raw)
		if err == nil && cidrContainedWithin(cidr, parent) {
			return true
		}
	}
	return false
}

func cidrContainedWithin(child, parent *net.IPNet) bool {
	if child == nil || parent == nil || child.IP == nil || parent.IP == nil {
		return false
	}
	childOnes, childBits := child.Mask.Size()
	parentOnes, parentBits := parent.Mask.Size()
	if childBits != parentBits || childOnes < parentOnes {
		return false
	}
	return parent.Contains(child.IP)
}

func parseIntSet(csv string) map[int]bool {
	parts := strings.Split(csv, ",")
	out := make(map[int]bool, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err == nil && n > 0 {
			out[n] = true
		}
	}
	return out
}

func parseStringSet(csv string) map[string]bool {
	parts := strings.Split(csv, ",")
	out := make(map[string]bool, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		out[p] = true
	}
	return out
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func splitCSVLower(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
