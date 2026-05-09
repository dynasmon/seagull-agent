package netcontext

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// buildTestIPNet constructs an *net.IPNet with the host address set (as
// iface.Addrs() returns on Linux), rather than the network address that
// net.ParseCIDR returns.
func buildTestIPNet(hostCIDR string) *net.IPNet {
	ip, ipnet, err := net.ParseCIDR(hostCIDR)
	if err != nil {
		panic(err)
	}
	// Replace the network address with the host address.
	ipnet.IP = ip.To4()
	if ipnet.IP == nil {
		ipnet.IP = ip.To16()
	}
	return ipnet
}

// unknownAddr is an addr type the builder does not recognise.
type unknownAddr struct{}

func (unknownAddr) Network() string { return "unknown" }
func (unknownAddr) String() string  { return "unknown://?" }

func TestBuildFromIfaceData_Normal(t *testing.T) {
	ipnet := buildTestIPNet("192.168.1.5/24")
	data := []ifaceData{
		{name: "eth0", addrs: []net.Addr{ipnet}},
	}
	nc := buildFromIfaceData(data, SourceHostObserved)

	if !nc.LocalIPs["192.168.1.5"] {
		t.Error("192.168.1.5 missing from LocalIPs")
	}
	if len(nc.LocalCIDRs) != 1 {
		t.Errorf("expected 1 CIDR, got %d", len(nc.LocalCIDRs))
	}
	if len(nc.Interfaces) != 1 || nc.Interfaces[0].Name != "eth0" {
		t.Errorf("unexpected interfaces: %+v", nc.Interfaces)
	}
	if nc.Source != SourceHostObserved {
		t.Errorf("unexpected source: %s", nc.Source)
	}
}

func TestBuildFromIfaceData_Loopback(t *testing.T) {
	ipnet := buildTestIPNet("127.0.0.1/8")
	data := []ifaceData{
		{name: "lo", addrs: []net.Addr{ipnet}},
	}
	nc := buildFromIfaceData(data, SourceHostObserved)

	if !nc.LocalIPs["127.0.0.1"] {
		t.Error("127.0.0.1 missing from LocalIPs")
	}
	if len(nc.Interfaces) == 0 || !nc.Interfaces[0].IsLoopback {
		t.Error("expected IsLoopback=true")
	}
	if nc.Interfaces[0].IsLinkLocal {
		t.Error("expected IsLinkLocal=false for loopback")
	}
}

func TestBuildFromIfaceData_LinkLocal(t *testing.T) {
	ipnet := buildTestIPNet("169.254.1.2/16")
	data := []ifaceData{
		{name: "eth0", addrs: []net.Addr{ipnet}},
	}
	nc := buildFromIfaceData(data, SourceHostObserved)

	if len(nc.Interfaces) == 0 || !nc.Interfaces[0].IsLinkLocal {
		t.Error("expected IsLinkLocal=true")
	}
	if nc.Interfaces[0].IsLoopback {
		t.Error("expected IsLoopback=false for link-local")
	}
}

func TestBuildFromIfaceData_Empty(t *testing.T) {
	nc := buildFromIfaceData(nil, SourceHostObserved)
	if len(nc.LocalIPs) != 0 {
		t.Errorf("expected empty LocalIPs, got %v", nc.LocalIPs)
	}
	if len(nc.Interfaces) != 0 {
		t.Errorf("expected no interfaces, got %v", nc.Interfaces)
	}
}

func TestBuildFromIfaceData_EmptyAddrs(t *testing.T) {
	data := []ifaceData{
		{name: "eth0", addrs: nil},
	}
	nc := buildFromIfaceData(data, SourceHostObserved)
	if len(nc.LocalIPs) != 0 {
		t.Error("expected empty LocalIPs for iface with no addrs")
	}
	if len(nc.Interfaces) != 0 {
		t.Error("interface with no addrs must not appear in Interfaces")
	}
}

func TestBuildFromIfaceData_UnknownAddrType(t *testing.T) {
	data := []ifaceData{
		{name: "eth0", addrs: []net.Addr{unknownAddr{}}},
	}
	nc := buildFromIfaceData(data, SourceHostObserved)
	if len(nc.LocalIPs) != 0 {
		t.Error("expected empty LocalIPs for unknown addr type")
	}
}

func TestBuildFromIfaceData_IPAddrType(t *testing.T) {
	ipAddr := &net.IPAddr{IP: net.ParseIP("10.0.0.1").To4()}
	data := []ifaceData{
		{name: "eth0", addrs: []net.Addr{ipAddr}},
	}
	nc := buildFromIfaceData(data, SourceHostObserved)
	if !nc.LocalIPs["10.0.0.1"] {
		t.Error("10.0.0.1 missing from LocalIPs for IPAddr input")
	}
	if len(nc.LocalCIDRs) != 1 {
		t.Errorf("expected 1 CIDR for host route, got %d", len(nc.LocalCIDRs))
	}
}

func TestBuildFromIfaceData_ContainerSource(t *testing.T) {
	ipnet := buildTestIPNet("172.17.0.2/16")
	data := []ifaceData{
		{name: "eth0", addrs: []net.Addr{ipnet}},
	}
	nc := buildFromIfaceData(data, SourceContainerObserved)
	if nc.Source != SourceContainerObserved {
		t.Errorf("expected container_observed, got %s", nc.Source)
	}
}

func TestDetectSource_DockerEnv(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".dockerenv"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectSource(dir); got != SourceContainerObserved {
		t.Errorf("expected container_observed via .dockerenv, got %s", got)
	}
}

func TestDetectSource_CgroupDocker(t *testing.T) {
	dir := t.TempDir()
	procDir := filepath.Join(dir, "proc", "1")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "12:devices:/docker/abc123\n11:cpu:/docker/abc123\n"
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectSource(dir); got != SourceContainerObserved {
		t.Errorf("expected container_observed via cgroup, got %s", got)
	}
}

func TestDetectSource_CgroupKubepods(t *testing.T) {
	dir := t.TempDir()
	procDir := filepath.Join(dir, "proc", "1")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "12:memory:/kubepods/burstable/pod-abc\n"
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectSource(dir); got != SourceContainerObserved {
		t.Errorf("expected container_observed via kubepods, got %s", got)
	}
}

func TestDetectSource_HostObserved(t *testing.T) {
	dir := t.TempDir()
	if got := detectSource(dir); got != SourceHostObserved {
		t.Errorf("expected host_observed for empty tmpdir, got %s", got)
	}
}

func TestFindCIDR_Match(t *testing.T) {
	ipnet := buildTestIPNet("192.168.1.5/24")
	nc := buildFromIfaceData([]ifaceData{{name: "eth0", addrs: []net.Addr{ipnet}}}, SourceHostObserved)

	got := nc.FindCIDR(net.ParseIP("192.168.1.200"))
	if got != "192.168.1.0/24" {
		t.Errorf("expected 192.168.1.0/24, got %q", got)
	}
}

func TestFindCIDR_NoMatch(t *testing.T) {
	ipnet := buildTestIPNet("192.168.1.5/24")
	nc := buildFromIfaceData([]ifaceData{{name: "eth0", addrs: []net.Addr{ipnet}}}, SourceHostObserved)

	got := nc.FindCIDR(net.ParseIP("10.0.0.1"))
	if got != "" {
		t.Errorf("expected empty for non-local, got %q", got)
	}
}

func TestFindCIDR_Nil(t *testing.T) {
	nc := buildFromIfaceData(nil, SourceHostObserved)
	if got := nc.FindCIDR(nil); got != "" {
		t.Errorf("expected empty for nil IP, got %q", got)
	}
}

func TestFindCIDR_LocalHostAddress(t *testing.T) {
	ipnet := buildTestIPNet("10.0.0.5/8")
	nc := buildFromIfaceData([]ifaceData{{name: "eth0", addrs: []net.Addr{ipnet}}}, SourceHostObserved)

	got := nc.FindCIDR(net.ParseIP("10.0.0.5"))
	if got != "10.0.0.0/8" {
		t.Errorf("expected 10.0.0.0/8, got %q", got)
	}
}

func TestEnrichEndpoints_InboundToLocal(t *testing.T) {
	ipnet := buildTestIPNet("192.168.1.5/24")
	nc := buildFromIfaceData([]ifaceData{{name: "eth0", addrs: []net.Addr{ipnet}}}, SourceHostObserved)

	extra := map[string]interface{}{}
	nc.EnrichEndpoints(extra, "1.2.3.4", "192.168.1.5")

	if extra["src_is_local_endpoint"] != false {
		t.Error("expected src not local")
	}
	if extra["dst_is_local_endpoint"] != true {
		t.Error("expected dst local")
	}
	if extra["src_in_agent_network"] != false {
		t.Error("expected remote src not in agent network")
	}
	if extra["dst_in_agent_network"] != true {
		t.Error("expected local dst in agent network")
	}
	if extra["network_context_source"] != string(SourceHostObserved) {
		t.Errorf("unexpected network_context_source: %v", extra["network_context_source"])
	}
	if extra["local_network_cidr"] != "192.168.1.0/24" {
		t.Errorf("expected local_network_cidr=192.168.1.0/24, got %v", extra["local_network_cidr"])
	}
}

func TestEnrichEndpoints_OutboundFromLocal(t *testing.T) {
	ipnet := buildTestIPNet("192.168.1.5/24")
	nc := buildFromIfaceData([]ifaceData{{name: "eth0", addrs: []net.Addr{ipnet}}}, SourceHostObserved)

	extra := map[string]interface{}{}
	nc.EnrichEndpoints(extra, "192.168.1.5", "8.8.8.8")

	if extra["src_is_local_endpoint"] != true {
		t.Error("expected src local")
	}
	if extra["dst_is_local_endpoint"] != false {
		t.Error("expected dst not local")
	}
	if extra["local_network_cidr"] != "192.168.1.0/24" {
		t.Errorf("expected local_network_cidr=192.168.1.0/24, got %v", extra["local_network_cidr"])
	}
}

func TestEnrichEndpoints_EmptySrc(t *testing.T) {
	ipnet := buildTestIPNet("10.0.0.2/24")
	nc := buildFromIfaceData([]ifaceData{{name: "eth0", addrs: []net.Addr{ipnet}}}, SourceHostObserved)

	extra := map[string]interface{}{}
	nc.EnrichEndpoints(extra, "", "10.0.0.2")

	if extra["src_is_local_endpoint"] != false {
		t.Error("empty src should not be local")
	}
	if extra["src_in_agent_network"] != false {
		t.Error("empty src should not be in agent network")
	}
	if extra["dst_is_local_endpoint"] != true {
		t.Error("expected dst local")
	}
}

func TestEnrichEndpoints_UnknownSource_NoCIDR(t *testing.T) {
	ipnet := buildTestIPNet("192.168.1.5/24")
	nc := buildFromIfaceData([]ifaceData{{name: "eth0", addrs: []net.Addr{ipnet}}}, SourceUnknown)

	extra := map[string]interface{}{}
	nc.EnrichEndpoints(extra, "1.2.3.4", "192.168.1.5")

	if _, ok := extra["local_network_cidr"]; ok {
		t.Error("local_network_cidr must not be set when source is unknown")
	}
}

func TestToInventoryMap(t *testing.T) {
	ipnet := buildTestIPNet("192.168.1.5/24")
	nc := buildFromIfaceData([]ifaceData{{name: "eth0", addrs: []net.Addr{ipnet}}}, SourceHostObserved)

	m := nc.ToInventoryMap()
	if m["source"] != string(SourceHostObserved) {
		t.Errorf("unexpected source in map: %v", m["source"])
	}
	ifaces, ok := m["interfaces"].([]map[string]interface{})
	if !ok || len(ifaces) != 1 {
		t.Fatalf("expected 1 interface in map, got %v", m["interfaces"])
	}
	if ifaces[0]["name"] != "eth0" {
		t.Errorf("unexpected name: %v", ifaces[0]["name"])
	}
}
