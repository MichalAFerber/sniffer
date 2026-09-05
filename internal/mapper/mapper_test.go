package mapper

import (
	"testing"
	"time"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

func TestARPReplyBecomesHost(t *testing.T) {
	m := New()
	now := time.Date(2026, 9, 5, 1, 0, 0, 0, time.UTC)
	m.Ingest([]obs.Observation{{
		Time:   now,
		Kind:   obs.KindARP,
		SrcMAC: "b8:27:eb:00:00:01",
		SrcIP:  "192.168.1.50",
		DstIP:  "192.168.1.1",
		Extra:  map[string]string{"op": "reply", "sha": "b8:27:eb:00:00:01"},
	}})
	hosts, _, _, _ := m.Snapshot(false)
	if len(hosts) != 1 {
		t.Fatalf("hosts=%d", len(hosts))
	}
	if hosts[0].IP != "192.168.1.50" {
		t.Fatalf("%+v", hosts[0])
	}
	if hosts[0].Vendor != "Raspberry Pi" {
		t.Fatalf("vendor %q", hosts[0].Vendor)
	}
}

func TestSYPACKService(t *testing.T) {
	m := New()
	m.Ingest([]obs.Observation{{
		Kind:    obs.KindTCP,
		SrcIP:   "192.168.1.5",
		DstIP:   "192.168.1.10",
		SrcPort: 80,
		DstPort: 54321,
		Proto:   "tcp",
		Extra:   map[string]string{"flags": "syn,ack", "service": "http"},
	}})
	_, svcs, _, _ := m.Snapshot(false)
	if len(svcs) != 1 || svcs[0].Port != 80 || svcs[0].Name != "http" {
		t.Fatalf("%+v", svcs)
	}
}

func TestFlushDropsFlows(t *testing.T) {
	m := New()
	m.Ingest([]obs.Observation{{
		Kind:    obs.KindTCP,
		SrcIP:   "192.168.1.2",
		DstIP:   "192.168.1.3",
		SrcPort: 9,
		DstPort: 9,
		Proto:   "tcp",
		Bytes:   40,
		Extra:   map[string]string{"flags": "syn"},
	}})
	_, _, flows, _ := m.Snapshot(true)
	if len(flows) != 1 {
		t.Fatalf("flows %d", len(flows))
	}
	_, _, flows, _ = m.Snapshot(false)
	if len(flows) != 0 {
		t.Fatalf("expected empty after flush, got %d", len(flows))
	}
}

func TestMulticastMACDropped(t *testing.T) {
	m := New()
	m.Ingest([]obs.Observation{{
		Kind:   obs.KindMDNS,
		SrcMAC: "01:00:5e:00:00:fb",
		SrcIP:  "224.0.0.251",
		Hostname: "x.local",
	}})
	hosts, _, _, _ := m.Snapshot(false)
	if len(hosts) != 0 {
		t.Fatalf("mcast should not be a host: %+v", hosts)
	}
}
