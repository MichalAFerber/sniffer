// Package scan is the portable mapper: local interfaces, reverse DNS,
// optional TCP probes, and mDNS queries. Linux adds ARP sweep via build tags.
package scan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MichalAFerber/sniffer/internal/decode"
	"github.com/MichalAFerber/sniffer/internal/obs"
)

type Options struct {
	Iface       string
	Ports       []uint16
	ProbeTCP    bool
	Timeout     time.Duration
	Concurrency int
	MaxHosts    int
}

func DefaultOptions() Options {
	return Options{
		Ports:       []uint16{22, 80, 443},
		Timeout:     300 * time.Millisecond,
		Concurrency: 32,
		MaxHosts:    256,
	}
}

type TargetNet struct {
	Iface  string
	MAC    net.HardwareAddr
	IP     net.IP
	Mask   net.IPMask
	Subnet *net.IPNet
}

func LocalNets(iface string) ([]TargetNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []TargetNet
	for _, ifi := range ifaces {
		if iface != "" && ifi.Name != iface {
			continue
		}
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}
			out = append(out, TargetNet{
				Iface:  ifi.Name,
				MAC:    ifi.HardwareAddr,
				IP:     ip,
				Mask:   ipn.Mask,
				Subnet: &net.IPNet{IP: ip.Mask(ipn.Mask), Mask: ipn.Mask},
			})
		}
	}
	return out, nil
}

func DefaultIface() string {
	nets, _ := LocalNets("")
	if len(nets) == 0 {
		return ""
	}
	return nets[0].Iface
}

// Discover runs one mapper pass. ARP sweep on Linux; TCP-alive elsewhere.
func Discover(ctx context.Context, opt Options) []obs.Observation {
	if opt.Timeout == 0 {
		opt.Timeout = 300 * time.Millisecond
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 32
	}
	if opt.MaxHosts <= 0 {
		opt.MaxHosts = 256
	}
	nets, err := LocalNets(opt.Iface)
	if err != nil || len(nets) == 0 {
		return nil
	}
	now := time.Now().UTC()
	var out []obs.Observation
	seen := map[string]struct{}{}

	add := func(o obs.Observation) {
		if o.Time.IsZero() {
			o.Time = now
		}
		key := o.SrcMAC + "|" + o.SrcIP
		if _, ok := seen[key]; ok && o.Kind == obs.KindHost {
			return
		}
		if o.Kind == obs.KindHost {
			seen[key] = struct{}{}
		}
		out = append(out, o)
	}

	for _, n := range nets {
		add(obs.Observation{
			Kind:   obs.KindHost,
			SrcMAC: n.MAC.String(),
			SrcIP:  n.IP.String(),
			Proto:  "local",
		})
		hosts := hostsIn(n.Subnet, n.IP, opt.MaxHosts)
		live := arpOrNil(ctx, n, hosts, opt.Timeout)
		if len(live) == 0 {
			live = tcpAlive(ctx, hosts, opt)
		}
		for _, h := range live {
			add(h)
		}
		if opt.ProbeTCP && len(opt.Ports) > 0 {
			for _, h := range live {
				ip := h.SrcIP
				if ip == "" {
					continue
				}
				for _, p := range tcpProbe(ctx, ip, opt) {
					add(p)
				}
			}
		}
		for _, h := range live {
			if h.SrcIP == "" {
				continue
			}
			if name := reverse(ctx, h.SrcIP, opt.Timeout); name != "" {
				o := h
				o.Kind = obs.KindHost
				o.Hostname = name
				o.Extra = map[string]string{"source": "ptr"}
				add(o)
			}
		}
	}
	for _, o := range MDNS(ctx, 2*time.Second) {
		add(o)
	}
	return out
}

func hostsIn(subnet *net.IPNet, self net.IP, max int) []net.IP {
	if subnet == nil {
		return nil
	}
	ones, bits := subnet.Mask.Size()
	if bits != 32 {
		return nil
	}
	// A /22 is 1022 hosts. Wider than that needs an explicit small cap.
	if ones < 22 && max > 1024 {
		return nil
	}
	var out []net.IP
	for ip := subnet.IP.Mask(subnet.Mask); subnet.Contains(ip); ip = nextIP(ip) {
		v4 := ip.To4()
		if v4 == nil {
			break
		}
		last := v4[3]
		if last == 0 || last == 255 {
			continue
		}
		if v4.Equal(self) {
			continue
		}
		cp := make(net.IP, 4)
		copy(cp, v4)
		out = append(out, cp)
		if len(out) >= max {
			break
		}
	}
	return out
}

func nextIP(ip net.IP) net.IP {
	v4 := ip.To4()
	if v4 == nil {
		return ip
	}
	out := make(net.IP, 4)
	copy(out, v4)
	for i := 3; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

func tcpAlive(ctx context.Context, hosts []net.IP, opt Options) []obs.Observation {
	ports := opt.Ports
	if len(ports) == 0 {
		ports = []uint16{80, 443, 22}
	}
	type hit struct {
		ip   string
		port uint16
	}
	ch := make(chan hit, 16)
	sem := make(chan struct{}, opt.Concurrency)
	var wg sync.WaitGroup
	for _, ip := range hosts {
		ip := ip.String()
		for _, p := range ports {
			p := p
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()
				d := net.Dialer{Timeout: opt.Timeout}
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(int(p))))
				if err != nil {
					return
				}
				_ = c.Close()
				select {
				case ch <- hit{ip: ip, port: p}:
				case <-ctx.Done():
				}
			}()
		}
	}
	go func() { wg.Wait(); close(ch) }()
	seen := map[string]struct{}{}
	var out []obs.Observation
	now := time.Now().UTC()
	for h := range ch {
		if _, ok := seen[h.ip]; !ok {
			seen[h.ip] = struct{}{}
			out = append(out, obs.Observation{
				Kind: obs.KindHost, SrcIP: h.ip, Time: now,
				Extra: map[string]string{"source": "tcp"},
			})
		}
		out = append(out, obs.Observation{
			Kind: obs.KindSvc, DstIP: h.ip, DstPort: h.port, Proto: "tcp", Time: now,
			Extra: map[string]string{"service": wellKnown(h.port), "source": "tcp"},
		})
	}
	return out
}

func tcpProbe(ctx context.Context, ip string, opt Options) []obs.Observation {
	return tcpAlive(ctx, []net.IP{net.ParseIP(ip)}, opt)
}

func reverse(ctx context.Context, ip string, d time.Duration) string {
	c, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(c, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func wellKnown(p uint16) string {
	switch p {
	case 22:
		return "ssh"
	case 80:
		return "http"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 3389:
		return "rdp"
	default:
		return ""
	}
}

// MDNS sends a few PTR queries and waits briefly for answers.
func MDNS(ctx context.Context, wait time.Duration) []obs.Observation {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()
	deadline := time.Now().Add(wait)
	_ = conn.SetDeadline(deadline)
	dst := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	queries := []string{
		"_services._dns-sd._udp.local",
		"_http._tcp.local",
		"_ssh._tcp.local",
		"_printer._tcp.local",
		"_ipp._tcp.local",
		"_googlecast._tcp.local",
		"_companion-link._tcp.local",
	}
	for i, q := range queries {
		msg := decode.EncodeQuery(uint16(0x1000+i), q, 12) // PTR
		_, _ = conn.WriteToUDP(msg, dst)
	}
	buf := make([]byte, 2048)
	var out []obs.Observation
	now := time.Now().UTC()
	for time.Now().Before(deadline) {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		frame := make([]byte, n)
		copy(frame, buf[:n])
		// Wrap as a synthetic observation; parseDNS via udp path needs Ethernet.
		// Call parse through a tiny UDP-shaped observation using decode.Frame
		// is overkill — reuse dnsObs by constructing a fake Ethernet? Skip.
		// We go through decode by building a minimal observation from the payload.
		o := obs.Observation{
			Kind:    obs.KindMDNS,
			SrcIP:   addr.IP.String(),
			SrcPort: uint16(addr.Port),
			DstPort: 5353,
			Proto:   "udp",
			Time:    now,
			Bytes:   n,
		}
		// parse via Frame is Ethernet-only. Use the exported EncodeQuery
		// sibling: re-decode by pretending this is a DNS payload through
		// a helper in this package.
		for _, extra := range mdnsAnswers(frame) {
			x := o
			x.Hostname = extra.qname
			x.Extra = map[string]string{"qname": extra.qname, "qtype": extra.qtype, "answer": extra.answer, "source": "mdns"}
			out = append(out, x)
			if extra.answer != "" && net.ParseIP(extra.answer) != nil {
				out = append(out, obs.Observation{
					Kind: obs.KindHost, SrcIP: extra.answer, Hostname: extra.qname, Time: now,
					Extra: map[string]string{"source": "mdns"},
				})
			}
		}
		select {
		case <-ctx.Done():
			return out
		default:
		}
	}
	return out
}

type rr struct{ qname, qtype, answer string }

func mdnsAnswers(b []byte) []rr {
	// Minimal: reuse decode by wrapping as Ethernet+IPv4+UDP. Too heavy.
	// parseDNS is unexported. Duplicate a thin call: Frame won't work on raw DNS.
	// Export isn't needed if we send the payload through a public helper.
	return parseDNSLite(b)
}

func parseDNSLite(b []byte) []rr {
	obsList := decode.Frame(fakeUDPv4(b, 5353, 5353))
	var out []rr
	for _, o := range obsList {
		if o.Kind != obs.KindMDNS && o.Kind != obs.KindDNS {
			continue
		}
		out = append(out, rr{
			qname:  first(o.ExtraGet("qname"), o.Hostname),
			qtype:  o.ExtraGet("qtype"),
			answer: o.ExtraGet("answer"),
		})
	}
	return out
}

func fakeUDPv4(payload []byte, src, dst uint16) []byte {
	// Ethernet + IPv4 + UDP around payload so decode.Frame can parse it.
	eth := make([]byte, 14+20+8+len(payload))
	eth[12] = 0x08
	eth[13] = 0x00
	ip := eth[14:]
	ip[0] = 0x45
	udpLen := 8 + len(payload)
	total := 20 + udpLen
	ip[2] = byte(total >> 8)
	ip[3] = byte(total)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], []byte{192, 168, 0, 1})
	copy(ip[16:20], []byte{224, 0, 0, 251})
	u := ip[20:]
	u[0] = byte(src >> 8)
	u[1] = byte(src)
	u[2] = byte(dst >> 8)
	u[3] = byte(dst)
	u[4] = byte(udpLen >> 8)
	u[5] = byte(udpLen)
	copy(u[8:], payload)
	return eth
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
