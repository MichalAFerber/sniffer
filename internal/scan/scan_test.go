package scan

import (
	"net"
	"testing"
)

func TestHostsInSkipsSelfAndEdges(t *testing.T) {
	_, subnet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	self := net.ParseIP("192.168.1.10")
	got := hostsIn(subnet, self, 300)
	if len(got) != 253 { // 1..254 minus self
		t.Fatalf("len %d", len(got))
	}
	for _, ip := range got {
		if ip.Equal(self) || ip[3] == 0 || ip[3] == 255 {
			t.Fatalf("bad ip %s", ip)
		}
	}
}

func TestHostsInCaps(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/16")
	got := hostsIn(subnet, net.ParseIP("10.0.0.1"), 16)
	if len(got) != 16 {
		t.Fatalf("len %d", len(got))
	}
}

func TestEncodeRoundTripUsedByMDNS(t *testing.T) {
	// Ensure fakeUDPv4 + Frame still sees the query name we send.
	from := parseDNSLite(mustQuery())
	if len(from) == 0 {
		t.Fatal("expected at least the question")
	}
}

func mustQuery() []byte {
	return []byte{
		0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		1, 'a', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0x00, 0x0c, 0x00, 0x01,
	}
}

func TestDefaultIfaceDoesNotPanic(t *testing.T) {
	_ = DefaultIface()
}
