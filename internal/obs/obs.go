// Package obs is the portable observation model shared by the sniffer,
// mapper, and uploader. Nothing here is OS-specific.
package obs

import "time"

type Kind string

const (
	KindARP  Kind = "arp"
	KindDHCP Kind = "dhcp"
	KindMDNS Kind = "mdns"
	KindDNS  Kind = "dns"
	KindSSDP Kind = "ssdp"
	KindTLS  Kind = "tls"
	KindHTTP Kind = "http"
	KindTCP  Kind = "tcp"
	KindUDP  Kind = "udp"
	KindHost Kind = "host"
	KindSvc  Kind = "service"
)

// Observation is one decoded fact from a packet or an active scan.
// Extra holds protocol-specific fields (sni, qname, hostname, flags, …).
type Observation struct {
	Time     time.Time         `json:"ts"`
	Kind     Kind              `json:"kind"`
	SrcMAC   string            `json:"src_mac,omitempty"`
	DstMAC   string            `json:"dst_mac,omitempty"`
	SrcIP    string            `json:"src_ip,omitempty"`
	DstIP    string            `json:"dst_ip,omitempty"`
	SrcPort  uint16            `json:"src_port,omitempty"`
	DstPort  uint16            `json:"dst_port,omitempty"`
	Proto    string            `json:"proto,omitempty"`
	Hostname string            `json:"hostname,omitempty"`
	Extra    map[string]string `json:"extra,omitempty"`
	Bytes    int               `json:"bytes,omitempty"`
}

func (o Observation) ExtraGet(k string) string {
	if o.Extra == nil {
		return ""
	}
	return o.Extra[k]
}

func (o *Observation) ExtraSet(k, v string) {
	if v == "" {
		return
	}
	if o.Extra == nil {
		o.Extra = map[string]string{}
	}
	o.Extra[k] = v
}

// Sensor is the agent identity attached to every ingest batch.
type Sensor struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
	Iface    string `json:"iface,omitempty"`
}

type Host struct {
	MAC       string    `json:"mac,omitempty"`
	IP        string    `json:"ip,omitempty"`
	IPv6      string    `json:"ipv6,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Vendor    string    `json:"vendor,omitempty"`
	Sources   []string  `json:"sources,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type Service struct {
	IP        string    `json:"ip"`
	Port      uint16    `json:"port"`
	Proto     string    `json:"proto"`
	Name      string    `json:"name,omitempty"`
	Banner    string    `json:"banner,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type Flow struct {
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port,omitempty"`
	DstPort   uint16    `json:"dst_port,omitempty"`
	Proto     string    `json:"proto"`
	Packets   uint64    `json:"packets"`
	Bytes     uint64    `json:"bytes"`
	Window    time.Time `json:"window_start"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type Name struct {
	QName     string    `json:"qname"`
	QType     string    `json:"qtype,omitempty"`
	Answer    string    `json:"answer,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
	Count     uint64    `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Batch is what the agent POSTs to the Worker.
type Batch struct {
	Sensor   Sensor    `json:"sensor"`
	SentAt   time.Time `json:"sent_at"`
	Hosts    []Host    `json:"hosts,omitempty"`
	Services []Service `json:"services,omitempty"`
	Flows    []Flow    `json:"flows,omitempty"`
	Names    []Name    `json:"names,omitempty"`
}
