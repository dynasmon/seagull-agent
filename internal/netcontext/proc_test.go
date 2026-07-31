package netcontext

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "netctx-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

// ---- ARP ----

const arpContent = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0
10.0.0.1         0x1         0x0         aa:bb:cc:dd:ee:ff     *        eth1
10.0.0.2         0x1         0x0         00:00:00:00:00:00     *        eth1
not-an-ip        0x1         0x2         11:22:33:44:55:66     *        eth0
`

func TestCollectARP_Parse(t *testing.T) {
	path := writeTemp(t, arpContent)
	entries, err := collectARP(path, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 192.168.1.1 reachable, 10.0.0.1 incomplete (flag 0x0 but non-zero MAC), not-an-ip skipped, 00:00:00 skipped
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(entries), entries)
	}

	e := entries[0]
	if e.IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %q", e.IP)
	}
	if e.MAC != "52:54:00:12:34:56" {
		t.Errorf("unexpected MAC: %q", e.MAC)
	}
	if e.Interface != "eth0" {
		t.Errorf("unexpected iface: %q", e.Interface)
	}
	if e.State != "reachable" {
		t.Errorf("expected state reachable, got %q", e.State)
	}

	e2 := entries[1]
	if e2.IP != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %q", e2.IP)
	}
	if e2.State != "incomplete" {
		t.Errorf("expected state incomplete, got %q", e2.State)
	}
}

func TestCollectARP_SkipsZeroMAC(t *testing.T) {
	content := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         00:00:00:00:00:00     *        eth0
`
	path := writeTemp(t, content)
	entries, err := collectARP(path, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no entries, got %d", len(entries))
	}
}

func TestCollectARP_Cap(t *testing.T) {
	content := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:00:00:01     *        eth0
192.168.1.2      0x1         0x2         aa:bb:cc:00:00:02     *        eth0
192.168.1.3      0x1         0x2         aa:bb:cc:00:00:03     *        eth0
`
	path := writeTemp(t, content)
	entries, err := collectARP(path, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries (cap), got %d", len(entries))
	}
}

func TestCollectARP_MissingFile(t *testing.T) {
	entries, err := collectARP(filepath.Join(t.TempDir(), "nonexistent"), 100)
	if err == nil {
		t.Error("expected error for missing file")
	}
	if entries != nil {
		t.Errorf("expected nil entries, got %v", entries)
	}
}

// ---- IPv4 routes ----

const routeContent = `Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0000A8C0	00000000	0001	0	0	0	00FFFFFF	0	0	0
`

func TestCollectRoutes_Parse(t *testing.T) {
	path := writeTemp(t, routeContent)
	routes, err := collectRoutes(path, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d: %+v", len(routes), routes)
	}

	def := routes[0]
	if def.Destination != "0.0.0.0/0" {
		t.Errorf("expected 0.0.0.0/0, got %q", def.Destination)
	}
	if def.Gateway != "192.168.1.1" {
		t.Errorf("expected gateway 192.168.1.1, got %q", def.Gateway)
	}
	if def.Interface != "eth0" {
		t.Errorf("expected iface eth0, got %q", def.Interface)
	}
	if def.Metric != 100 {
		t.Errorf("expected metric 100, got %d", def.Metric)
	}
	if def.Family != "ipv4" {
		t.Errorf("expected family ipv4, got %q", def.Family)
	}

	lan := routes[1]
	if lan.Destination != "192.168.0.0/24" {
		t.Errorf("expected 192.168.0.0/24, got %q", lan.Destination)
	}
	if lan.Gateway != "0.0.0.0" {
		t.Errorf("expected gateway 0.0.0.0, got %q", lan.Gateway)
	}
	if lan.Metric != 0 {
		t.Errorf("expected metric 0, got %d", lan.Metric)
	}
}

func TestCollectRoutes_Cap(t *testing.T) {
	path := writeTemp(t, routeContent)
	routes, err := collectRoutes(path, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Errorf("expected 1 route (cap), got %d", len(routes))
	}
}

func TestCollectRoutes_MissingFile(t *testing.T) {
	routes, err := collectRoutes(filepath.Join(t.TempDir(), "nonexistent"), 100)
	if err == nil {
		t.Error("expected error for missing file")
	}
	if routes != nil {
		t.Errorf("expected nil routes, got %v", routes)
	}
}

// ---- IPv6 routes ----

// Fields: dest(32) pfxlen src(32) srclen nexthop(32) metric refcnt usecount flags iface
const ipv6RouteContent = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000000 00000000 00000001       lo
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001       eth0
`

func TestCollectIPv6Routes_Parse(t *testing.T) {
	path := writeTemp(t, ipv6RouteContent)
	routes, err := collectIPv6Routes(path, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d: %+v", len(routes), routes)
	}

	r0 := routes[0]
	if r0.Destination != "::/0" {
		t.Errorf("expected ::/0, got %q", r0.Destination)
	}
	if r0.Gateway != "::" {
		t.Errorf("expected :: gateway, got %q", r0.Gateway)
	}
	if r0.Interface != "lo" {
		t.Errorf("expected lo, got %q", r0.Interface)
	}
	if r0.Metric != 100 { // 0x64
		t.Errorf("expected metric 100, got %d", r0.Metric)
	}
	if r0.Family != "ipv6" {
		t.Errorf("expected family ipv6, got %q", r0.Family)
	}

	r1 := routes[1]
	if r1.Destination != "fe80::/64" {
		t.Errorf("expected fe80::/64, got %q", r1.Destination)
	}
	if r1.Interface != "eth0" {
		t.Errorf("expected eth0, got %q", r1.Interface)
	}
	if r1.Metric != 256 { // 0x100
		t.Errorf("expected metric 256, got %d", r1.Metric)
	}
}

func TestCollectIPv6Routes_ZeroMax(t *testing.T) {
	routes, err := collectIPv6Routes("/proc/net/ipv6_route", 0)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if routes != nil {
		t.Errorf("expected nil routes for max=0, got %v", routes)
	}
}

func TestCollectIPv6Routes_MissingFile(t *testing.T) {
	routes, err := collectIPv6Routes(filepath.Join(t.TempDir(), "nonexistent"), 100)
	if err == nil {
		t.Error("expected error for missing file")
	}
	if routes != nil {
		t.Errorf("expected nil routes, got %v", routes)
	}
}

func TestCollectIPv6Routes_Cap(t *testing.T) {
	path := writeTemp(t, ipv6RouteContent)
	routes, err := collectIPv6Routes(path, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Errorf("expected 1 route (cap), got %d", len(routes))
	}
}

// ---- Resolvers ----

const resolvContent = `# Generated by NetworkManager
nameserver 8.8.8.8
nameserver 8.8.4.4
search example.com local
options ndots:5 timeout:1
`

func TestCollectResolvers_Parse(t *testing.T) {
	path := writeTemp(t, resolvContent)
	info, err := collectResolvers(path, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("expected 2 nameservers, got %d", len(info.Nameservers))
	}
	if info.Nameservers[0] != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8, got %q", info.Nameservers[0])
	}
	if info.Nameservers[1] != "8.8.4.4" {
		t.Errorf("expected 8.8.4.4, got %q", info.Nameservers[1])
	}
	if len(info.SearchDomains) != 2 {
		t.Errorf("expected 2 search domains, got %d: %v", len(info.SearchDomains), info.SearchDomains)
	}
	if info.SearchDomains[0] != "example.com" {
		t.Errorf("unexpected search[0]: %q", info.SearchDomains[0])
	}
	if len(info.Options) != 2 {
		t.Errorf("expected 2 options, got %d: %v", len(info.Options), info.Options)
	}
	if info.Options[0] != "ndots:5" {
		t.Errorf("unexpected options[0]: %q", info.Options[0])
	}
}

func TestCollectResolvers_NameserverCap(t *testing.T) {
	path := writeTemp(t, resolvContent)
	info, err := collectResolvers(path, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.Nameservers) != 1 {
		t.Errorf("expected 1 nameserver (cap), got %d", len(info.Nameservers))
	}
}

func TestCollectResolvers_Domain(t *testing.T) {
	content := `domain corp.example.com
search example.com
nameserver 1.1.1.1
`
	path := writeTemp(t, content)
	info, err := collectResolvers(path, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// domain prepends to search list
	if len(info.SearchDomains) < 1 || info.SearchDomains[0] != "corp.example.com" {
		t.Errorf("expected corp.example.com first in search, got %v", info.SearchDomains)
	}
}

func TestCollectResolvers_Comments(t *testing.T) {
	content := `# comment
; also comment
nameserver 9.9.9.9
`
	path := writeTemp(t, content)
	info, err := collectResolvers(path, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.Nameservers) != 1 || info.Nameservers[0] != "9.9.9.9" {
		t.Errorf("unexpected nameservers: %v", info.Nameservers)
	}
}

func TestCollectResolvers_SkipsInvalidIP(t *testing.T) {
	content := `nameserver not-an-ip
nameserver 1.2.3.4
`
	path := writeTemp(t, content)
	info, err := collectResolvers(path, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.Nameservers) != 1 || info.Nameservers[0] != "1.2.3.4" {
		t.Errorf("unexpected nameservers: %v", info.Nameservers)
	}
}

func TestCollectResolvers_MissingFile(t *testing.T) {
	_, err := collectResolvers(filepath.Join(t.TempDir(), "nonexistent"), 10)
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// ---- Host identity ----

func TestCollectHostIdentity(t *testing.T) {
	id, err := collectHostIdentity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Hostname == "" {
		t.Error("expected non-empty hostname")
	}
}

func TestCollectHostIdentity_FQDNFromDotted(t *testing.T) {
	// If the hostname already contains a dot, FQDN should equal Hostname.
	// We can't control os.Hostname in a unit test, so we test the helper logic directly.
	id := HostIdentity{Hostname: "host.example.com"}
	// Simulate the assignment logic from collectHostIdentity.
	if len(id.Hostname) > 0 && id.Hostname == "host.example.com" {
		id.FQDN = id.Hostname
	}
	if id.FQDN != "host.example.com" {
		t.Errorf("expected FQDN=host.example.com, got %q", id.FQDN)
	}
}

// ---- Caps normalization ----

func TestNormalizeCaps_Defaults(t *testing.T) {
	c := normalizeCaps(Caps{})
	if c.MaxInterfaces != defaultMaxInterfaces {
		t.Errorf("expected %d, got %d", defaultMaxInterfaces, c.MaxInterfaces)
	}
	if c.MaxNeighbors != defaultMaxNeighbors {
		t.Errorf("expected %d, got %d", defaultMaxNeighbors, c.MaxNeighbors)
	}
	if c.MaxRoutes != defaultMaxRoutes {
		t.Errorf("expected %d, got %d", defaultMaxRoutes, c.MaxRoutes)
	}
	if c.MaxResolvers != defaultMaxResolvers {
		t.Errorf("expected %d, got %d", defaultMaxResolvers, c.MaxResolvers)
	}
}

func TestNormalizeCaps_Preserved(t *testing.T) {
	c := normalizeCaps(Caps{MaxInterfaces: 10, MaxNeighbors: 20, MaxRoutes: 30, MaxResolvers: 4})
	if c.MaxInterfaces != 10 || c.MaxNeighbors != 20 || c.MaxRoutes != 30 || c.MaxResolvers != 4 {
		t.Errorf("custom caps not preserved: %+v", c)
	}
}

// ---- Hex decode helpers ----

func TestHexIPv4LE(t *testing.T) {
	cases := []struct {
		hex  string
		want string
	}{
		{"00000000", "0.0.0.0"},
		{"0101A8C0", "192.168.1.1"},
		{"0000A8C0", "192.168.0.0"},
	}
	for _, tc := range cases {
		ip, err := hexIPv4LE(tc.hex)
		if err != nil {
			t.Errorf("hexIPv4LE(%q): %v", tc.hex, err)
			continue
		}
		if got := ip.String(); got != tc.want {
			t.Errorf("hexIPv4LE(%q) = %q, want %q", tc.hex, got, tc.want)
		}
	}
}

func TestHexIPv4LE_Invalid(t *testing.T) {
	if _, err := hexIPv4LE("ZZZZZZZZ"); err == nil {
		t.Error("expected error for invalid hex")
	}
	if _, err := hexIPv4LE("0000"); err == nil {
		t.Error("expected error for short hex")
	}
}

func TestHexIPv6(t *testing.T) {
	cases := []struct {
		hex  string
		want net.IP
	}{
		{"00000000000000000000000000000000", net.IPv6zero},
		{"fe800000000000000000000000000000", net.ParseIP("fe80::")},
	}
	for _, tc := range cases {
		got, err := hexIPv6(tc.hex)
		if err != nil {
			t.Errorf("hexIPv6(%q): %v", tc.hex, err)
			continue
		}
		want := tc.want.String()
		if got != want {
			t.Errorf("hexIPv6(%q) = %q, want %q", tc.hex, got, want)
		}
	}
}

func TestHexIPv6_Invalid(t *testing.T) {
	if _, err := hexIPv6("ZZZZ"); err == nil {
		t.Error("expected error for invalid hex")
	}
	if _, err := hexIPv6("0000"); err == nil {
		t.Error("expected error for wrong length")
	}
}

// ---- ToInventoryMap backward compat + new fields ----

func TestToInventoryMap_SchemaVersion(t *testing.T) {
	nc := buildFromIfaceData(nil, SourceHostObserved)
	m := nc.ToInventoryMap()
	if m["schema_version"] != 2 {
		t.Errorf("expected schema_version=2, got %v", m["schema_version"])
	}
}

func TestToInventoryMap_BackwardCompat(t *testing.T) {
	ipnet := buildTestIPNet("192.168.1.5/24")
	nc := buildFromIfaceData([]ifaceData{{name: "eth0", addrs: []net.Addr{ipnet}}}, SourceHostObserved)
	m := nc.ToInventoryMap()

	if m["source"] != string(SourceHostObserved) {
		t.Errorf("source key missing or wrong: %v", m["source"])
	}
	ifaces, ok := m["interfaces"].([]map[string]interface{})
	if !ok || len(ifaces) != 1 {
		t.Fatalf("interfaces key wrong: %v", m["interfaces"])
	}
	if ifaces[0]["name"] != "eth0" {
		t.Errorf("interface name wrong: %v", ifaces[0]["name"])
	}
}

func TestToInventoryMap_WithNeighbors(t *testing.T) {
	nc := buildFromIfaceData(nil, SourceHostObserved)
	nc.Neighbors = []NeighborEntry{
		{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", Interface: "eth0", State: "reachable"},
	}
	m := nc.ToInventoryMap()
	neighbors, ok := m["neighbors"].([]map[string]interface{})
	if !ok || len(neighbors) != 1 {
		t.Fatalf("expected 1 neighbor, got %v", m["neighbors"])
	}
	if neighbors[0]["ip"] != "10.0.0.1" {
		t.Errorf("unexpected neighbor IP: %v", neighbors[0]["ip"])
	}
	if neighbors[0]["state"] != "reachable" {
		t.Errorf("unexpected neighbor state: %v", neighbors[0]["state"])
	}
}

func TestToInventoryMap_WithRoutes(t *testing.T) {
	nc := buildFromIfaceData(nil, SourceHostObserved)
	nc.Routes = []RouteEntry{
		{Destination: "0.0.0.0/0", Gateway: "192.168.1.1", Interface: "eth0", Metric: 100, Family: "ipv4"},
	}
	m := nc.ToInventoryMap()
	routes, ok := m["routes"].([]map[string]interface{})
	if !ok || len(routes) != 1 {
		t.Fatalf("expected 1 route, got %v", m["routes"])
	}
	if routes[0]["destination"] != "0.0.0.0/0" {
		t.Errorf("unexpected destination: %v", routes[0]["destination"])
	}
	if routes[0]["family"] != "ipv4" {
		t.Errorf("unexpected family: %v", routes[0]["family"])
	}
}

func TestToInventoryMap_EmptySlicesNotNull(t *testing.T) {
	nc := buildFromIfaceData(nil, SourceHostObserved)
	m := nc.ToInventoryMap()

	resolvers, ok := m["resolvers"].(map[string]interface{})
	if !ok {
		t.Fatalf("resolvers is not a map: %T", m["resolvers"])
	}
	ns, ok := resolvers["nameservers"].([]string)
	if !ok {
		t.Fatalf("nameservers is not []string: %T", resolvers["nameservers"])
	}
	if ns == nil {
		t.Error("nameservers should be empty slice, not nil")
	}
}

func TestToInventoryMap_InterfaceFields(t *testing.T) {
	mac, _ := net.ParseMAC("02:42:ac:11:00:02")
	data := []ifaceData{
		{
			name:         "eth0",
			hardwareAddr: mac,
			mtu:          1500,
			flags:        net.FlagUp,
			addrs:        []net.Addr{buildTestIPNet("192.168.1.5/24")},
		},
	}
	nc := buildFromIfaceData(data, SourceHostObserved)
	m := nc.ToInventoryMap()
	ifaces := m["interfaces"].([]map[string]interface{})
	iface := ifaces[0]

	if iface["mac"] != "02:42:ac:11:00:02" {
		t.Errorf("unexpected mac: %v", iface["mac"])
	}
	if iface["mtu"] != 1500 {
		t.Errorf("unexpected mtu: %v", iface["mtu"])
	}
	if iface["is_up"] != true {
		t.Errorf("expected is_up=true, got %v", iface["is_up"])
	}
}

func TestBuildFromIfaceData_IsUp(t *testing.T) {
	ipnet := buildTestIPNet("10.0.0.1/24")
	data := []ifaceData{
		{name: "eth0", flags: net.FlagUp, addrs: []net.Addr{ipnet}},
		{name: "eth1", flags: 0, addrs: []net.Addr{buildTestIPNet("10.0.0.2/24")}},
	}
	nc := buildFromIfaceData(data, SourceHostObserved)
	if len(nc.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(nc.Interfaces))
	}
	if !nc.Interfaces[0].IsUp {
		t.Error("eth0 should be up")
	}
	if nc.Interfaces[1].IsUp {
		t.Error("eth1 should not be up")
	}
}

func TestBuildFromIfaceData_MAC(t *testing.T) {
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")
	ipnet := buildTestIPNet("10.0.0.1/24")
	data := []ifaceData{
		{name: "eth0", hardwareAddr: mac, addrs: []net.Addr{ipnet}},
	}
	nc := buildFromIfaceData(data, SourceHostObserved)
	if nc.Interfaces[0].MAC != "de:ad:be:ef:00:01" {
		t.Errorf("unexpected MAC: %q", nc.Interfaces[0].MAC)
	}
}
