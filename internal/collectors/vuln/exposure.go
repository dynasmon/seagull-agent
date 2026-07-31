package vuln

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ExposureOptions struct {
	HostRoot string
	MaxPorts int
}

type HostExposure struct {
	CollectedAt     time.Time
	ListeningPorts  []int
	ExposedPorts    []int
	HighRiskPorts   []int
	ServiceHints    []string
	PortServices    []PortService
	ListeningTCP    int
	ListeningUDP    int
	HasExposedPorts bool
	SurfaceScore    int
}

type PortService struct {
	Proto   string
	Port    int
	Process string
	PID     int
	Exe     string
	Cmdline string
}

func (h HostExposure) ToEvidence() map[string]interface{} {
	return map[string]interface{}{
		"collected_at":      h.CollectedAt,
		"listening_ports":   h.ListeningPorts,
		"exposed_ports":     h.ExposedPorts,
		"high_risk_ports":   h.HighRiskPorts,
		"service_hints":     h.ServiceHints,
		"port_services":     h.PortServices,
		"listening_tcp":     h.ListeningTCP,
		"listening_udp":     h.ListeningUDP,
		"has_exposed_ports": h.HasExposedPorts,
		"surface_score":     h.SurfaceScore,
	}
}

func (h HostExposure) MatchesPackage(pkgName string) bool {
	name := strings.ToLower(strings.TrimSpace(pkgName))
	if name == "" {
		return false
	}
	if !h.HasExposedPorts {
		return false
	}
	if containsAny(name, genericServerKeywords) {
		return true
	}
	for _, s := range h.ServiceHints {
		if strings.Contains(name, s) || strings.Contains(s, name) {
			return true
		}
	}
	for _, p := range h.ExposedPorts {
		if containsAny(name, packageKeywordsByPort[p]) {
			return true
		}
	}
	return false
}

func CollectHostExposure(opts ExposureOptions) (HostExposure, error) {
	out := HostExposure{CollectedAt: time.Now().UTC()}
	if opts.MaxPorts <= 0 {
		opts.MaxPorts = 512
	}

	procRoot := "/proc"
	if hr := strings.TrimSpace(opts.HostRoot); hr != "" {
		cand := filepath.Join(hr, "proc")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			procRoot = cand
		}
	}

	tcp4, err1 := readProcPorts(filepath.Join(procRoot, "net/tcp"), true, false)
	tcp6, err2 := readProcPorts(filepath.Join(procRoot, "net/tcp6"), true, true)
	udp4, err3 := readProcPorts(filepath.Join(procRoot, "net/udp"), false, false)
	udp6, err4 := readProcPorts(filepath.Join(procRoot, "net/udp6"), false, true)
	if err1 != nil && err2 != nil && err3 != nil && err4 != nil {
		return out, fmt.Errorf("failed to read proc net sockets")
	}

	ports := map[int]bool{}
	exposed := map[int]bool{}
	highRisk := map[int]bool{}
	inodes := map[uint64]bool{}
	sockets := make([]procPort, 0, 128)

	for _, item := range append(append(tcp4, tcp6...), append(udp4, udp6...)...) {
		sockets = append(sockets, item)
		ports[item.Port] = true
		if item.Inode > 0 {
			inodes[item.Inode] = true
		}
		if item.Proto == "tcp" {
			out.ListeningTCP++
		} else {
			out.ListeningUDP++
		}
		if !item.IsLoopback {
			exposed[item.Port] = true
			if highRiskPorts[item.Port] {
				highRisk[item.Port] = true
			}
		}
	}

	out.ListeningPorts = sortedKeysInt(ports, opts.MaxPorts)
	out.ExposedPorts = sortedKeysInt(exposed, opts.MaxPorts)
	out.HighRiskPorts = sortedKeysInt(highRisk, opts.MaxPorts)
	out.HasExposedPorts = len(out.ExposedPorts) > 0
	procs := findProcessByInode(procRoot, inodes)
	out.PortServices = inferPortServices(sockets, procs)
	out.ServiceHints = inferServiceHints(out.PortServices)
	out.SurfaceScore = computeSurfaceScore(out)
	return out, nil
}

type procPort struct {
	Port       int
	Proto      string
	IsLoopback bool
	Inode      uint64
}

func readProcPorts(path string, tcp bool, ipv6 bool) ([]procPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make([]procPort, 0, 64)
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		st := strings.TrimSpace(fields[3])
		if tcp {
			if st != "0A" { // LISTEN
				continue
			}
		} else if st != "07" && st != "0A" { // UDP unconnected/listening
			continue
		}

		ipHex, port, ok := splitAddr(fields[1])
		if !ok || port <= 0 || port > 65535 {
			continue
		}
		isLoopback := false
		if ipv6 {
			isLoopback = isIPv6LoopbackHex(ipHex)
		} else {
			isLoopback = isIPv4LoopbackHex(ipHex)
		}
		proto := "udp"
		if tcp {
			proto = "tcp"
		}
		inode, _ := strconv.ParseUint(strings.TrimSpace(fields[9]), 10, 64)
		out = append(out, procPort{Port: port, Proto: proto, IsLoopback: isLoopback, Inode: inode})
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func splitAddr(v string) (string, int, bool) {
	i := strings.LastIndex(v, ":")
	if i <= 0 || i+1 >= len(v) {
		return "", 0, false
	}
	ipHex := strings.TrimSpace(v[:i])
	portHex := strings.TrimSpace(v[i+1:])
	p, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", 0, false
	}
	return ipHex, int(p), true
}

func isIPv4LoopbackHex(ipHex string) bool {
	if len(ipHex) != 8 {
		return false
	}
	b, err := hex.DecodeString(ipHex)
	if err != nil || len(b) != 4 {
		return false
	}
	ip := net.IPv4(b[3], b[2], b[1], b[0])
	return ip.IsLoopback()
}

func isIPv6LoopbackHex(ipHex string) bool {
	if len(ipHex) != 32 {
		return false
	}
	b, err := hex.DecodeString(ipHex)
	if err != nil || len(b) != 16 {
		return false
	}
	// /proc/net/tcp6 encodes IPv6 in little-endian 32-bit chunks.
	raw := make([]byte, 16)
	for i := 0; i < 16; i += 4 {
		raw[i] = b[i+3]
		raw[i+1] = b[i+2]
		raw[i+2] = b[i+1]
		raw[i+3] = b[i]
	}
	ip := net.IP(raw)
	return ip.IsLoopback()
}

type procInfo struct {
	PID     int
	Process string
	Exe     string
	Cmdline string
}

func inferServiceHints(portServices []PortService) []string {
	out := make([]string, 0, len(portServices))
	seen := map[string]bool{}
	for _, ps := range portServices {
		svc := normalizeServiceName(ps.Process, ps.Exe, ps.Cmdline)
		if svc == "" || seen[svc] {
			continue
		}
		seen[svc] = true
		out = append(out, svc)
	}
	sort.Strings(out)
	return out
}

func findProcessByInode(procRoot string, target map[uint64]bool) map[uint64]procInfo {
	out := map[uint64]procInfo{}
	if len(target) == 0 {
		return out
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(de.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fdDir := filepath.Join(procRoot, de.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var pinfo procInfo
		hasInfo := false
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := parseSocketInode(link)
			if !ok || !target[inode] {
				continue
			}
			if _, exists := out[inode]; exists {
				continue
			}
			if !hasInfo {
				pinfo = procInfo{
					PID:     pid,
					Process: readFirstLine(filepath.Join(procRoot, de.Name(), "comm")),
					Exe:     readLinkTrim(filepath.Join(procRoot, de.Name(), "exe")),
					Cmdline: readCmdline(filepath.Join(procRoot, de.Name(), "cmdline")),
				}
				hasInfo = true
			}
			out[inode] = pinfo
		}
		if len(out) >= len(target) {
			break
		}
	}
	return out
}

func inferPortServices(sockets []procPort, procs map[uint64]procInfo) []PortService {
	seen := map[string]bool{}
	out := make([]PortService, 0, len(sockets))
	for _, s := range sockets {
		if s.IsLoopback {
			continue
		}
		p := procs[s.Inode]
		key := fmt.Sprintf("%s:%d:%d:%s", s.Proto, s.Port, p.PID, p.Process)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, PortService{
			Proto:   s.Proto,
			Port:    s.Port,
			Process: normalizeText(p.Process, 64),
			PID:     p.PID,
			Exe:     normalizeText(p.Exe, 256),
			Cmdline: normalizeText(p.Cmdline, 512),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port == out[j].Port {
			if out[i].Proto == out[j].Proto {
				return out[i].Process < out[j].Process
			}
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func parseSocketInode(link string) (uint64, bool) {
	s := strings.TrimSpace(link)
	if !strings.HasPrefix(s, "socket:[") || !strings.HasSuffix(s, "]") {
		return 0, false
	}
	n := strings.TrimSuffix(strings.TrimPrefix(s, "socket:["), "]")
	v, err := strconv.ParseUint(strings.TrimSpace(n), 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}

func readFirstLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func readCmdline(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := strings.ReplaceAll(string(b), "\x00", " ")
	return strings.TrimSpace(s)
}

func readLinkTrim(path string) string {
	s, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

func normalizeServiceName(process, exe, cmdline string) string {
	candidates := []string{process, filepath.Base(exe), filepath.Base(firstToken(cmdline))}
	for _, c := range candidates {
		c = strings.ToLower(strings.TrimSpace(c))
		c = strings.TrimSuffix(c, ".bin")
		if c == "" || c == "-" || c == "." {
			continue
		}
		return normalizeText(c, 64)
	}
	return ""
}

func firstToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	p := strings.Fields(s)
	if len(p) == 0 {
		return ""
	}
	return p[0]
}

func normalizeText(s string, max int) string {
	s = strings.TrimSpace(s)
	if max > 0 && len(s) > max {
		s = s[:max]
	}
	return s
}

func computeSurfaceScore(h HostExposure) int {
	score := 0
	score += min(len(h.ExposedPorts)*6, 36)
	score += min(len(h.HighRiskPorts)*10, 40)
	if len(h.ServiceHints) > 0 {
		score += min(len(h.ServiceHints)*4, 16)
	}
	if h.HasExposedPorts {
		score += 8
	}
	if score > 100 {
		return 100
	}
	return score
}

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func sortedKeysInt(m map[int]bool, max int) []int {
	out := make([]int, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Ints(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

var highRiskPorts = map[int]bool{
	22: true, 80: true, 443: true, 445: true, 3389: true, 5432: true, 3306: true,
	6379: true, 9200: true, 5601: true, 6443: true, 2375: true, 2376: true,
}

var genericServerKeywords = []string{
	"server", "daemon", "proxy", "http", "nginx", "apache", "httpd", "caddy", "traefik",
	"haproxy", "openssh", "sshd", "samba", "xrdp", "mysql", "mariadb", "postgres",
	"redis", "mongodb", "elastic", "kibana", "docker", "containerd", "kube",
}

var packageKeywordsByPort = map[int][]string{
	22:   {"ssh", "openssh"},
	53:   {"bind", "dns", "dnsmasq", "unbound"},
	80:   {"nginx", "apache", "httpd", "caddy", "traefik", "haproxy"},
	443:  {"nginx", "apache", "httpd", "caddy", "traefik", "haproxy"},
	445:  {"samba", "smb"},
	3389: {"xrdp", "rdp"},
	3306: {"mysql", "mariadb"},
	5432: {"postgres"},
	6379: {"redis"},
	9200: {"elasticsearch", "opensearch"},
	5601: {"kibana"},
	2375: {"docker"},
	2376: {"docker"},
	6443: {"kube", "kubernetes"},
}
