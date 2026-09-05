package decode

import (
	"encoding/binary"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

func dhcp(srcMAC, dstMAC, srcIP, dstIP string, b []byte) []obs.Observation {
	// BOOTP fixed: 236 bytes + magic cookie 4 + options
	if len(b) < 240 {
		return nil
	}
	magic := binary.BigEndian.Uint32(b[236:240])
	if magic != 0x63825363 {
		return nil
	}
	op := b[0]
	xid := binary.BigEndian.Uint32(b[4:8])
	yiaddr := ip4(b[16:20])
	chaddr := mac(b[28:34])
	o := obs.Observation{
		Kind:   obs.KindDHCP,
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
		SrcIP:  srcIP,
		DstIP:  dstIP,
		Proto:  "udp",
		Bytes:  len(b),
	}
	o.SrcPort, o.DstPort = 68, 67
	if op == 2 {
		o.SrcPort, o.DstPort = 67, 68
	}
	o.ExtraSet("chaddr", chaddr)
	o.ExtraSet("xid", hex8(xid))
	if yiaddr != "0.0.0.0" {
		o.ExtraSet("yiaddr", yiaddr)
		o.SrcIP = prefer(o.SrcIP, yiaddr)
	}
	opts := b[240:]
	for len(opts) >= 2 {
		code := opts[0]
		if code == 255 {
			break
		}
		if code == 0 {
			opts = opts[1:]
			continue
		}
		n := int(opts[1])
		opts = opts[2:]
		if n > len(opts) {
			break
		}
		val := opts[:n]
		opts = opts[n:]
		switch code {
		case 12: // hostname
			o.Hostname = sanitizeHost(string(val))
		case 50: // requested IP
			if n == 4 {
				o.ExtraSet("requested_ip", ip4(val))
				if o.SrcIP == "0.0.0.0" {
					o.SrcIP = ip4(val)
				}
			}
		case 53: // message type
			if n >= 1 {
				o.ExtraSet("msg", dhcpMsg(val[0]))
			}
		case 54: // server id
			if n == 4 {
				o.ExtraSet("server_id", ip4(val))
			}
		case 61: // client id
			if n >= 7 && val[0] == 1 {
				o.ExtraSet("client_mac", mac(val[1:7]))
			}
		}
	}
	if o.SrcMAC == "" || o.SrcMAC == "00:00:00:00:00:00" {
		o.SrcMAC = chaddr
	}
	return []obs.Observation{o}
}

func dhcpMsg(t byte) string {
	switch t {
	case 1:
		return "discover"
	case 2:
		return "offer"
	case 3:
		return "request"
	case 4:
		return "decline"
	case 5:
		return "ack"
	case 6:
		return "nak"
	case 7:
		return "release"
	case 8:
		return "inform"
	default:
		return ""
	}
}

func hex8(v uint32) string {
	const hex = "0123456789abcdef"
	var out [8]byte
	for i := 7; i >= 0; i-- {
		out[i] = hex[v&0xf]
		v >>= 4
	}
	return string(out[:])
}

func prefer(cur, next string) string {
	if cur == "" || cur == "0.0.0.0" {
		return next
	}
	return cur
}

func sanitizeHost(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0 {
			break
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' {
			out = append(out, c)
		}
	}
	return string(out)
}
