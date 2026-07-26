package pcapx_test

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/collectors/pcapx"
	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/model"
)

func TestBufferDedupAndDrain(t *testing.T) {
	b := pcapx.NewBuffer(time.Minute, 10)
	if !b.Push("k1", model.NetEvent{}) {
		t.Fatal("first push should be added")
	}
	if b.Push("k1", model.NetEvent{}) {
		t.Fatal("duplicate within ttl should be dropped")
	}
	if !b.Push("k2", model.NetEvent{}) {
		t.Fatal("distinct key should be added")
	}
	out := b.Drain()
	if len(out) != 2 {
		t.Fatalf("drain len = %d, want 2", len(out))
	}
	if got := b.Drain(); got != nil {
		t.Fatalf("second drain = %v, want nil", got)
	}
}

func TestBufferBatchCap(t *testing.T) {
	b := pcapx.NewBuffer(time.Minute, 1)
	if !b.Push("a", model.NetEvent{}) {
		t.Fatal("first push should be added")
	}
	if b.Push("b", model.NetEvent{}) {
		t.Fatal("push beyond maxBatch should be dropped")
	}
}

func TestDropByIP(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	deny := []*net.IPNet{cidr}

	if !pcapx.DropByIP("bad", "1.1.1.1", false, false, false, nil) {
		t.Error("unparseable src should drop")
	}
	if !pcapx.DropByIP("127.0.0.1", "1.1.1.1", true, false, false, nil) {
		t.Error("loopback with skipLoopback should drop")
	}
	if pcapx.DropByIP("8.8.8.8", "1.1.1.1", true, true, false, nil) {
		t.Error("public pair should not drop")
	}
	if !pcapx.DropByIP("10.1.2.3", "1.1.1.1", false, false, false, deny) {
		t.Error("src in deny cidr should drop")
	}
	if !pcapx.DropByIP("192.168.1.2", "192.168.1.3", false, false, true, nil) {
		t.Error("private-to-private with flag should drop")
	}
	if pcapx.DropByIP("192.168.1.2", "192.168.1.3", false, false, false, nil) {
		t.Error("private-to-private without flag should not drop")
	}
}

func TestSkippableIP(t *testing.T) {
	if !pcapx.SkippableIP(nil, false, false) {
		t.Error("nil ip should be skippable")
	}
	if !pcapx.SkippableIP(net.ParseIP("127.0.0.1"), true, false) {
		t.Error("loopback should be skippable when enabled")
	}
	if pcapx.SkippableIP(net.ParseIP("8.8.8.8"), true, true) {
		t.Error("public ip should not be skippable")
	}
}

func TestIPInCIDRs(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.0.0/16")
	cidrs := []*net.IPNet{cidr}
	if !pcapx.IPInCIDRs(net.ParseIP("192.168.5.5"), cidrs) {
		t.Error("ip within cidr should match")
	}
	if pcapx.IPInCIDRs(net.ParseIP("10.0.0.1"), cidrs) {
		t.Error("ip outside cidr should not match")
	}
	if pcapx.IPInCIDRs(nil, cidrs) {
		t.Error("nil ip should not match")
	}
}

func TestTCPFlags(t *testing.T) {
	if got := pcapx.TCPFlags(&layers.TCP{SYN: true, ACK: true}); got != "SYN|ACK" {
		t.Errorf("TCPFlags = %q, want SYN|ACK", got)
	}
	if got := pcapx.TCPFlags(&layers.TCP{}); got != "" {
		t.Errorf("TCPFlags empty = %q, want empty string", got)
	}
}
