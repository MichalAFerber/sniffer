package mapper

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MichalAFerber/sniffer/internal/obs"
	"github.com/MichalAFerber/sniffer/internal/oui"
)

const (
	maxHosts    = 4096
	maxServices = 8192
	maxFlows    = 8192
	maxNames    = 4096
)

type Mapper struct {
	mu       sync.Mutex
	hosts    map[string]*obs.Host
	services map[string]*obs.Service
	flows    map[string]*obs.Flow
	names    map[string]*obs.Name
}

func New() *Mapper {
	return &Mapper{
		hosts:    map[string]*obs.Host{},
		services: map[string]*obs.Service{},
		flows:    map[string]*obs.Flow{},
		names:    map[string]*obs.Name{},
	}
}

func (m *Mapper) Ingest(list []obs.Observation) {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range list {
		if o.Time.IsZero() {
			o.Time = now
		} else {
			o.Time = o.Time.UTC()
		}
		m.ingestOne(o)
	}
}

func (m *Mapper) ingestOne(o obs.Observation) {
	t := o.Time
	mac := unicastMAC(o.SrcMAC)
	ip := hostIP(o.SrcIP)
	if o.Kind == obs.KindARP {
		mac = unicastMAC(first(o.ExtraGet("sha"), o.SrcMAC))
	}
	if o.Kind == obs.KindDHCP {
		mac = unicastMAC(first(o.ExtraGet("chaddr"), o.SrcMAC))
		if alt := hostIP(o.ExtraGet("yiaddr")); alt != "" {
			ip = alt
		} else if alt := hostIP(o.ExtraGet("requested_ip")); alt != "" {
			ip = alt
		}
	}
	if mac != "" || ip != "" {
		m.touchHost(mac, ip, "", o.Hostname, string(o.Kind), t)
	}

	switch o.Kind {
	case obs.KindTCP:
		flags := o.ExtraGet("flags")
		// SYN-ACK: src is the service. SYN: dst is a candidate.
		if strings.Contains(flags, "syn") && strings.Contains(flags, "ack") {
			m.touchService(o.SrcIP, o.SrcPort, "tcp", o.ExtraGet("service"), "", t)
		} else if strings.Contains(flags, "syn") && !strings.Contains(flags, "ack") {
			m.touchService(o.DstIP, o.DstPort, "tcp", o.ExtraGet("service"), "", t)
		}
		m.touchFlow(o, t)
	case obs.KindUDP, obs.KindMDNS, obs.KindDNS, obs.KindDHCP, obs.KindSSDP:
		if o.DstPort != 0 && !isEphemeral(o.DstPort) {
			m.touchService(o.DstIP, o.DstPort, "udp", o.ExtraGet("service"), "", t)
		}
		m.touchFlow(o, t)
	case obs.KindTLS:
		m.touchService(o.DstIP, o.DstPort, "tcp", "https", o.Hostname, t)
		if o.Hostname != "" {
			m.touchName(o.Hostname, "SNI", o.DstIP, o.SrcIP, t)
		}
	case obs.KindHTTP:
		m.touchService(o.DstIP, o.DstPort, "tcp", "http", o.Hostname, t)
		if o.Hostname != "" {
			m.touchName(o.Hostname, "HTTP", o.DstIP, o.SrcIP, t)
		}
	case obs.KindSvc:
		m.touchService(o.DstIP, o.DstPort, first(o.Proto, "tcp"), o.ExtraGet("service"), o.Hostname, t)
	case obs.KindHost:
		mac := unicastMAC(o.SrcMAC)
		ip := hostIP(o.SrcIP)
		ipv6 := ""
		if ip6 := net.ParseIP(o.SrcIP); ip6 != nil && ip6.To4() == nil {
			ipv6 = o.SrcIP
			ip = ""
		}
		m.touchHost(mac, ip, ipv6, o.Hostname, first(o.ExtraGet("source"), "scan"), t)
	}

	if o.Kind == obs.KindDNS || o.Kind == obs.KindMDNS {
		q := first(o.ExtraGet("qname"), o.Hostname)
		a := o.ExtraGet("answer")
		if q != "" {
			m.touchName(q, o.ExtraGet("qtype"), a, o.SrcIP, t)
		}
		if a != "" && looksIP(a) {
			m.touchHost("", a, "", q, string(o.Kind), t)
		}
	}
	if o.Kind == obs.KindSSDP && o.Hostname != "" && looksIP(o.Hostname) {
		m.touchHost("", o.Hostname, "", o.ExtraGet("server"), "ssdp", t)
	}
}

func (m *Mapper) touchHost(mac, ip, ipv6, hostname, source string, t time.Time) {
	mac = unicastMAC(mac)
	if ip != "" && !usableIP(ip) {
		ip = ""
	}
	if ipv6 != "" && !usableIP(ipv6) {
		ipv6 = ""
	}
	if mac == "" && ip == "" && ipv6 == "" {
		return
	}
	key := hostKey(mac, ip, ipv6)
	h, ok := m.hosts[key]
	if !ok {
		if len(m.hosts) >= maxHosts {
			m.evictHosts()
		}
		h = &obs.Host{MAC: mac, IP: ip, IPv6: ipv6, FirstSeen: t, LastSeen: t}
		m.hosts[key] = h
	}
	if t.Before(h.FirstSeen) {
		h.FirstSeen = t
	}
	if t.After(h.LastSeen) {
		h.LastSeen = t
	}
	if hostname != "" && !looksIP(hostname) {
		h.Hostname = hostname
	}
	if ip != "" && h.IP == "" {
		h.IP = ip
	}
	if ipv6 != "" && h.IPv6 == "" {
		h.IPv6 = ipv6
	}
	if mac != "" && h.MAC == "" {
		h.MAC = mac
	}
	if h.Vendor == "" && h.MAC != "" {
		h.Vendor = oui.Lookup(h.MAC)
	}
	if source != "" && !contains(h.Sources, source) {
		h.Sources = append(h.Sources, source)
	}
}

func (m *Mapper) touchService(ip string, port uint16, proto, name, banner string, t time.Time) {
	if !usableIP(ip) || port == 0 {
		return
	}
	key := ip + "|" + proto + "|" + itoa(port)
	s, ok := m.services[key]
	if !ok {
		if len(m.services) >= maxServices {
			m.evictServices()
		}
		s = &obs.Service{IP: ip, Port: port, Proto: proto, FirstSeen: t, LastSeen: t}
		m.services[key] = s
	}
	if t.After(s.LastSeen) {
		s.LastSeen = t
	}
	if t.Before(s.FirstSeen) {
		s.FirstSeen = t
	}
	if name != "" {
		s.Name = name
	}
	if banner != "" {
		s.Banner = banner
	}
}

func (m *Mapper) touchFlow(o obs.Observation, t time.Time) {
	src, dst := hostIP(o.SrcIP), hostIP(o.DstIP)
	if src == "" || dst == "" {
		return
	}
	window := t.Truncate(time.Minute)
	key := src + "|" + dst + "|" + o.Proto + "|" + itoa(o.SrcPort) + "|" + itoa(o.DstPort) + "|" + window.Format(time.RFC3339)
	f, ok := m.flows[key]
	if !ok {
		if len(m.flows) >= maxFlows {
			m.evictFlows()
		}
		f = &obs.Flow{
			SrcIP: src, DstIP: dst, SrcPort: o.SrcPort, DstPort: o.DstPort,
			Proto: o.Proto, Window: window, FirstSeen: t, LastSeen: t,
		}
		m.flows[key] = f
	}
	f.Packets++
	if o.Bytes > 0 {
		f.Bytes += uint64(o.Bytes)
	}
	if t.After(f.LastSeen) {
		f.LastSeen = t
	}
}

func (m *Mapper) touchName(q, qtype, answer, client string, t time.Time) {
	if q == "" {
		return
	}
	key := strings.ToLower(q) + "|" + qtype + "|" + answer
	n, ok := m.names[key]
	if !ok {
		if len(m.names) >= maxNames {
			m.evictNames()
		}
		n = &obs.Name{QName: q, QType: qtype, Answer: answer, ClientIP: client, FirstSeen: t, LastSeen: t}
		m.names[key] = n
	}
	n.Count++
	if t.After(n.LastSeen) {
		n.LastSeen = t
	}
	if n.ClientIP == "" {
		n.ClientIP = client
	}
}

// Snapshot copies current state. If flush is true, flows and names that
// have already been reported are dropped so the next upload is a delta.
func (m *Mapper) Snapshot(flush bool) (hosts []obs.Host, services []obs.Service, flows []obs.Flow, names []obs.Name) {
	m.mu.Lock()
	defer m.mu.Unlock()
	hosts = make([]obs.Host, 0, len(m.hosts))
	for _, h := range m.hosts {
		hosts = append(hosts, *h)
	}
	services = make([]obs.Service, 0, len(m.services))
	for _, s := range m.services {
		services = append(services, *s)
	}
	flows = make([]obs.Flow, 0, len(m.flows))
	for _, f := range m.flows {
		flows = append(flows, *f)
	}
	names = make([]obs.Name, 0, len(m.names))
	for _, n := range m.names {
		names = append(names, *n)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].LastSeen.After(hosts[j].LastSeen) })
	if flush {
		m.flows = map[string]*obs.Flow{}
		m.names = map[string]*obs.Name{}
	}
	return
}

func (m *Mapper) Counts() (h, s, f, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.hosts), len(m.services), len(m.flows), len(m.names)
}

func (m *Mapper) evictHosts() {
	oldest := ""
	var t time.Time
	first := true
	for k, h := range m.hosts {
		if first || h.LastSeen.Before(t) {
			oldest, t, first = k, h.LastSeen, false
		}
	}
	delete(m.hosts, oldest)
}

func (m *Mapper) evictServices() {
	oldest := ""
	var t time.Time
	first := true
	for k, s := range m.services {
		if first || s.LastSeen.Before(t) {
			oldest, t, first = k, s.LastSeen, false
		}
	}
	delete(m.services, oldest)
}

func (m *Mapper) evictFlows() {
	oldest := ""
	var t time.Time
	first := true
	for k, f := range m.flows {
		if first || f.LastSeen.Before(t) {
			oldest, t, first = k, f.LastSeen, false
		}
	}
	delete(m.flows, oldest)
}

func (m *Mapper) evictNames() {
	oldest := ""
	var t time.Time
	first := true
	for k, n := range m.names {
		if first || n.LastSeen.Before(t) {
			oldest, t, first = k, n.LastSeen, false
		}
	}
	delete(m.names, oldest)
}

func hostKey(mac, ip, ipv6 string) string {
	if mac != "" {
		return "m:" + mac
	}
	if ip != "" {
		return "4:" + ip
	}
	return "6:" + ipv6
}

func unicastMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "00:00:00:00:00:00" || s == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	if len(s) >= 8 && (s[:8] == "01:00:5e" || s[:5] == "33:33") {
		return ""
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) < 6 {
		return ""
	}
	if hw[0]&1 == 1 { // I/G bit
		return ""
	}
	return hw.String()
}

func hostIP(s string) string {
	if !usableIP(s) {
		return ""
	}
	return s
}

func usableIP(s string) bool {
	if s == "" || s == "0.0.0.0" || s == "255.255.255.255" || s == "::" {
		return false
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !ip.IsMulticast() && !ip.IsLoopback() && !ip.IsUnspecified()
}

func looksIP(s string) bool {
	return net.ParseIP(s) != nil
}

func isEphemeral(p uint16) bool { return p >= 32768 }

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func itoa(p uint16) string {
	if p == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	v := int(p)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
