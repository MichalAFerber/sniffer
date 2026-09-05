//go:build linux

package scan

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"time"

	"github.com/MichalAFerber/sniffer/internal/obs"
	"golang.org/x/sys/unix"
)

func ARPSupported() bool { return true }

func ARPSweep(ctx context.Context, n TargetNet, hosts []net.IP, timeout time.Duration) []obs.Observation {
	if n.MAC == nil || len(n.MAC) < 6 || n.IP == nil {
		return fromProcARP(n.Iface)
	}
	ifi, err := net.InterfaceByName(n.Iface)
	if err != nil {
		return fromProcARP(n.Iface)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return fromProcARP(n.Iface)
	}
	defer unix.Close(fd)
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ARP),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, addr); err != nil {
		return fromProcARP(n.Iface)
	}
	tv := unix.NsecToTimeval(int64(50 * time.Millisecond))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	srcMAC := n.MAC
	if len(srcMAC) > 6 {
		srcMAC = srcMAC[:6]
	}
	srcIP := n.IP.To4()
	for _, dst := range hosts {
		select {
		case <-ctx.Done():
			return collectARP(fd, timeout)
		default:
		}
		frame := arpRequest(srcMAC, srcIP, dst.To4())
		_ = unix.Sendto(fd, frame, 0, addr)
		time.Sleep(2 * time.Millisecond)
	}
	return mergeARP(collectARP(fd, timeout), fromProcARP(n.Iface))
}

func collectARP(fd int, wait time.Duration) []obs.Observation {
	deadline := time.Now().Add(wait)
	buf := make([]byte, 128)
	now := time.Now().UTC()
	seen := map[string]struct{}{}
	var out []obs.Observation
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}
		if n < 42 {
			continue
		}
		etype := binary.BigEndian.Uint16(buf[12:14])
		if etype != 0x0806 {
			continue
		}
		arp := buf[14:]
		if len(arp) < 28 {
			continue
		}
		oper := binary.BigEndian.Uint16(arp[6:8])
		if oper != 2 {
			continue
		}
		sha := net.HardwareAddr(arp[8:14]).String()
		spa := net.IP(arp[14:18]).String()
		key := sha + "|" + spa
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, obs.Observation{
			Kind:   obs.KindHost,
			SrcMAC: sha,
			SrcIP:  spa,
			Time:   now,
			Extra:  map[string]string{"source": "arp"},
		})
	}
	return out
}

func arpRequest(srcMAC net.HardwareAddr, srcIP, dstIP net.IP) []byte {
	b := make([]byte, 42)
	for i := 0; i < 6; i++ {
		b[i] = 0xff
	}
	copy(b[6:12], srcMAC)
	b[12], b[13] = 0x08, 0x06
	arp := b[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	copy(arp[8:14], srcMAC)
	copy(arp[14:18], srcIP)
	copy(arp[24:28], dstIP)
	return b
}

func fromProcARP(iface string) []obs.Observation {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil
	}
	now := time.Now().UTC()
	var out []obs.Observation
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		if iface != "" && f[5] != iface {
			continue
		}
		hw := strings.ToLower(f[3])
		if hw == "00:00:00:00:00:00" {
			continue
		}
		out = append(out, obs.Observation{
			Kind:   obs.KindHost,
			SrcIP:  f[0],
			SrcMAC: hw,
			Time:   now,
			Extra:  map[string]string{"source": "arp-table"},
		})
	}
	return out
}

func mergeARP(a, b []obs.Observation) []obs.Observation {
	seen := map[string]struct{}{}
	var out []obs.Observation
	for _, x := range append(a, b...) {
		k := x.SrcMAC + "|" + x.SrcIP
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, x)
	}
	return out
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
