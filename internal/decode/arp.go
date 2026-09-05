package decode

import (
	"encoding/binary"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

func arp(srcMAC, dstMAC string, b []byte) []obs.Observation {
	// hwtype(2) ptype(2) hlen plen oper(2) sha spa tha tpa
	if len(b) < 28 {
		return nil
	}
	hwtype := binary.BigEndian.Uint16(b[0:2])
	ptype := binary.BigEndian.Uint16(b[2:4])
	hlen, plen := int(b[4]), int(b[5])
	oper := binary.BigEndian.Uint16(b[6:8])
	if hwtype != 1 || ptype != etherTypeIPv4 || hlen != 6 || plen != 4 {
		return nil
	}
	sha := mac(b[8:14])
	spa := ip4(b[14:18])
	tpa := ip4(b[24:28])
	o := obs.Observation{
		Kind:   obs.KindARP,
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
		SrcIP:  spa,
		DstIP:  tpa,
		Proto:  "arp",
		Bytes:  len(b),
	}
	o.ExtraSet("sha", sha)
	switch oper {
	case 1:
		o.ExtraSet("op", "request")
	case 2:
		o.ExtraSet("op", "reply")
	default:
		o.ExtraSet("op", "other")
	}
	return []obs.Observation{o}
}
