// Package decode turns raw Ethernet frames into observations.
// Pure Go, no cgo: safe to compile on every GOOS.
package decode

import (
	"encoding/binary"
	"net"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806
	etherTypeVLAN = 0x8100
	etherTypeIPv6 = 0x86dd

	protoICMP  = 1
	protoTCP   = 6
	protoUDP   = 17
	protoICMPv6 = 58
)

// Frame decodes one Ethernet frame. Returns nil if the bytes are too short
// or the packet is uninteresting (incomplete headers, empty).
func Frame(b []byte) []obs.Observation {
	if len(b) < 14 {
		return nil
	}
	dstMAC := mac(b[0:6])
	srcMAC := mac(b[6:12])
	etype := binary.BigEndian.Uint16(b[12:14])
	payload := b[14:]
	if etype == etherTypeVLAN {
		if len(payload) < 4 {
			return nil
		}
		etype = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}
	switch etype {
	case etherTypeARP:
		return arp(srcMAC, dstMAC, payload)
	case etherTypeIPv4:
		return ipv4(srcMAC, dstMAC, payload)
	case etherTypeIPv6:
		return ipv6(srcMAC, dstMAC, payload)
	default:
		return nil
	}
}

func mac(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return net.HardwareAddr(b[:6]).String()
}

func ip4(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return net.IP(b[:4]).String()
}

func ip6(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return net.IP(b[:16]).String()
}

func wellKnownUDP(port uint16) string {
	switch port {
	case 53:
		return "dns"
	case 67, 68:
		return "dhcp"
	case 123:
		return "ntp"
	case 137:
		return "nbns"
	case 1900:
		return "ssdp"
	case 5353:
		return "mdns"
	case 5355:
		return "llmnr"
	default:
		return ""
	}
}

func wellKnownTCP(port uint16) string {
	switch port {
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 139:
		return "netbios"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 515:
		return "lpd"
	case 548:
		return "afp"
	case 631:
		return "ipp"
	case 3389:
		return "rdp"
	case 5357:
		return "wsd"
	case 8080:
		return "http-alt"
	case 8443:
		return "https-alt"
	default:
		return ""
	}
}
