package decode

import (
	"encoding/binary"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

func ipv4(srcMAC, dstMAC string, b []byte) []obs.Observation {
	if len(b) < 20 {
		return nil
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return nil
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total > 0 && total < len(b) {
		b = b[:total]
	}
	if len(b) < ihl {
		return nil
	}
	proto := b[9]
	src := ip4(b[12:16])
	dst := ip4(b[16:20])
	payload := b[ihl:]
	switch proto {
	case protoTCP:
		return tcp(srcMAC, dstMAC, src, dst, payload, "tcp")
	case protoUDP:
		return udp(srcMAC, dstMAC, src, dst, payload)
	case protoICMP:
		o := obs.Observation{
			Kind: obs.KindUDP, SrcMAC: srcMAC, DstMAC: dstMAC,
			SrcIP: src, DstIP: dst, Proto: "icmp", Bytes: len(b),
		}
		return []obs.Observation{o}
	default:
		return nil
	}
}

func ipv6(srcMAC, dstMAC string, b []byte) []obs.Observation {
	if len(b) < 40 {
		return nil
	}
	next := b[6]
	src := ip6(b[8:24])
	dst := ip6(b[24:40])
	payload := b[40:]
	// Skip a single hop-by-hop / dest / routing header. Good enough for LAN.
	for i := 0; i < 3 && (next == 0 || next == 43 || next == 60) && len(payload) >= 2; i++ {
		hdrLen := int(payload[1]+1) * 8
		if hdrLen < 8 || len(payload) < hdrLen {
			return nil
		}
		next = payload[0]
		payload = payload[hdrLen:]
	}
	switch next {
	case protoTCP:
		return tcp(srcMAC, dstMAC, src, dst, payload, "tcp")
	case protoUDP:
		return udp(srcMAC, dstMAC, src, dst, payload)
	default:
		return nil
	}
}
