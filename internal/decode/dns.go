package decode

import (
	"encoding/binary"
	"strings"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

type dnsRR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
}

func dnsObs(kind obs.Kind, base obs.Observation, b []byte) []obs.Observation {
	qs, ans, ok := parseDNS(b)
	if !ok {
		return []obs.Observation{base}
	}
	out := make([]obs.Observation, 0, 1+len(qs)+len(ans))
	base.Kind = kind
	if len(qs) > 0 {
		base.Hostname = qs[0].Name
		base.ExtraSet("qname", qs[0].Name)
		base.ExtraSet("qtype", dnsType(qs[0].Type))
	}
	out = append(out, base)
	for _, a := range ans {
		if a.Data == "" && a.Name == "" {
			continue
		}
		o := base
		o.Hostname = a.Name
		o.ExtraSet("qname", a.Name)
		o.ExtraSet("qtype", dnsType(a.Type))
		o.ExtraSet("answer", a.Data)
		out = append(out, o)
	}
	return out
}

func parseDNS(b []byte) (qs []dnsRR, ans []dnsRR, ok bool) {
	if len(b) < 12 {
		return nil, nil, false
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	off := 12
	if qd > 16 || an > 32 {
		// Bound work on garbage / amplification leftovers.
		qd = min(qd, 16)
		an = min(an, 32)
	}
	for i := 0; i < qd; i++ {
		name, n, ok := readName(b, off, 0)
		if !ok {
			return qs, ans, len(qs)+len(ans) > 0
		}
		off = n
		if off+4 > len(b) {
			return qs, ans, true
		}
		typ := binary.BigEndian.Uint16(b[off : off+2])
		class := binary.BigEndian.Uint16(b[off+2 : off+4])
		off += 4
		qs = append(qs, dnsRR{Name: name, Type: typ, Class: class})
	}
	for i := 0; i < an; i++ {
		name, n, ok := readName(b, off, 0)
		if !ok {
			return qs, ans, true
		}
		off = n
		if off+10 > len(b) {
			return qs, ans, true
		}
		typ := binary.BigEndian.Uint16(b[off : off+2])
		class := binary.BigEndian.Uint16(b[off+2 : off+4])
		ttl := binary.BigEndian.Uint32(b[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
		off += 10
		if rdlen < 0 || off+rdlen > len(b) {
			return qs, ans, true
		}
		rdata := b[off : off+rdlen]
		off += rdlen
		ans = append(ans, dnsRR{
			Name:  name,
			Type:  typ,
			Class: class,
			TTL:   ttl,
			Data:  rdataString(typ, rdata, b, off-rdlen),
		})
	}
	return qs, ans, true
}

func rdataString(typ uint16, rdata, msg []byte, rdataOff int) string {
	switch typ {
	case 1: // A
		if len(rdata) == 4 {
			return ip4(rdata)
		}
	case 28: // AAAA
		if len(rdata) == 16 {
			return ip6(rdata)
		}
	case 12, 2, 5, 39: // PTR, NS, CNAME, DNAME
		name, _, ok := readName(msg, rdataOff, 0)
		if ok {
			return name
		}
		return string(rdata)
	case 16: // TXT
		return txtRdata(rdata)
	case 33: // SRV
		if len(rdata) >= 7 {
			name, _, ok := readName(msg, rdataOff+6, 0)
			if ok {
				return name
			}
		}
	}
	return ""
}

func txtRdata(b []byte) string {
	var parts []string
	for len(b) > 0 {
		n := int(b[0])
		b = b[1:]
		if n > len(b) {
			break
		}
		parts = append(parts, string(b[:n]))
		b = b[n:]
	}
	return strings.Join(parts, " ")
}

func readName(msg []byte, off, hops int) (string, int, bool) {
	if hops > 10 || off >= len(msg) {
		return "", off, false
	}
	var labels []string
	start := off
	jumped := false
	end := off
	for {
		if off >= len(msg) {
			return "", start, false
		}
		l := int(msg[off])
		if l == 0 {
			off++
			if !jumped {
				end = off
			}
			break
		}
		if l&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return "", start, false
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if !jumped {
				end = off + 2
			}
			rest, _, ok := readName(msg, ptr, hops+1)
			if !ok {
				return "", start, false
			}
			if rest != "" {
				labels = append(labels, rest)
			}
			return strings.Join(labels, "."), end, true
		}
		if l&0xc0 != 0 {
			return "", start, false
		}
		off++
		if l == 0 || off+l > len(msg) {
			return "", start, false
		}
		labels = append(labels, string(msg[off:off+l]))
		off += l
		if !jumped {
			end = off
		}
		if len(labels) > 64 {
			return "", start, false
		}
	}
	return strings.Join(labels, "."), end, true
}

func dnsType(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 12:
		return "PTR"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return ""
	}
}

// EncodeQuery builds a tiny DNS/mDNS question. Recursion desired is off
// (mDNS-friendly). id is in network order as-is.
func EncodeQuery(id uint16, name string, qtype uint16) []byte {
	var b []byte
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[4:6], 1) // qdcount
	b = append(b, hdr[:]...)
	for _, lab := range strings.Split(name, ".") {
		if lab == "" {
			continue
		}
		if len(lab) > 63 {
			lab = lab[:63]
		}
		b = append(b, byte(len(lab)))
		b = append(b, lab...)
	}
	b = append(b, 0)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN
	b = append(b, tail[:]...)
	return b
}
