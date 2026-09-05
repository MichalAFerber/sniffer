package decode

import (
	"encoding/binary"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

func tcp(srcMAC, dstMAC, srcIP, dstIP string, b []byte, proto string) []obs.Observation {
	if len(b) < 20 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(b[0:2])
	dstPort := binary.BigEndian.Uint16(b[2:4])
	dataOff := int(b[12]>>4) * 4
	if dataOff < 20 || len(b) < dataOff {
		return nil
	}
	flags := b[13]
	payload := b[dataOff:]
	o := obs.Observation{
		Kind:    obs.KindTCP,
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   proto,
		Bytes:   len(b),
	}
	var names []string
	if flags&0x02 != 0 {
		names = append(names, "syn")
	}
	if flags&0x10 != 0 {
		names = append(names, "ack")
	}
	if flags&0x01 != 0 {
		names = append(names, "fin")
	}
	if flags&0x04 != 0 {
		names = append(names, "rst")
	}
	if len(names) > 0 {
		joined := names[0]
		for i := 1; i < len(names); i++ {
			joined += "," + names[i]
		}
		o.ExtraSet("flags", joined)
	}
	if name := wellKnownTCP(dstPort); name != "" {
		o.ExtraSet("service", name)
	} else if name := wellKnownTCP(srcPort); name != "" {
		o.ExtraSet("service", name)
	}

	out := []obs.Observation{o}
	if len(payload) == 0 {
		return out
	}
	if dstPort == 443 || srcPort == 443 || dstPort == 8443 || srcPort == 8443 {
		if sni := tlsSNI(payload); sni != "" {
			t := o
			t.Kind = obs.KindTLS
			t.Hostname = sni
			t.ExtraSet("sni", sni)
			out = append(out, t)
		}
	}
	if dstPort == 80 || srcPort == 80 || dstPort == 8080 || srcPort == 8080 {
		if host := httpHost(payload); host != "" {
			h := o
			h.Kind = obs.KindHTTP
			h.Hostname = host
			h.ExtraSet("host", host)
			out = append(out, h)
		}
	}
	return out
}

func udp(srcMAC, dstMAC, srcIP, dstIP string, b []byte) []obs.Observation {
	if len(b) < 8 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(b[0:2])
	dstPort := binary.BigEndian.Uint16(b[2:4])
	payload := b[8:]
	o := obs.Observation{
		Kind:    obs.KindUDP,
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   "udp",
		Bytes:   len(b),
	}
	if name := wellKnownUDP(dstPort); name != "" {
		o.ExtraSet("service", name)
	} else if name := wellKnownUDP(srcPort); name != "" {
		o.ExtraSet("service", name)
	}

	ports := [2]uint16{srcPort, dstPort}
	is := func(p uint16) bool { return ports[0] == p || ports[1] == p }

	switch {
	case is(67) || is(68):
		if d := dhcp(srcMAC, dstMAC, srcIP, dstIP, payload); len(d) > 0 {
			return d
		}
	case is(53):
		if d := dnsObs(obs.KindDNS, o, payload); len(d) > 0 {
			return d
		}
	case is(5353):
		if d := dnsObs(obs.KindMDNS, o, payload); len(d) > 0 {
			return d
		}
	case is(5355):
		if d := dnsObs(obs.KindMDNS, o, payload); len(d) > 0 {
			return d
		}
	case is(1900):
		if d := ssdp(o, payload); len(d) > 0 {
			return d
		}
	}
	return []obs.Observation{o}
}
