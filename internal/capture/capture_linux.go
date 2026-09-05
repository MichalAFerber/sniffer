//go:build linux

package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

type linuxHandle struct {
	fd    int
	buf   []byte
	iface string
}

func Open(iface string, snaplen int, promisc bool) (Handle, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("iface %s: %w", iface, err)
	}
	if snaplen <= 0 {
		snaplen = 2048
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("af_packet socket: %w (need CAP_NET_RAW)", err)
	}
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", iface, err)
	}
	if promisc {
		mreq := unix.PacketMreq{
			Ifindex: int32(ifi.Index),
			Type:    unix.PACKET_MR_PROMISC,
		}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("promisc %s: %w (need CAP_NET_ADMIN)", iface, err)
		}
	}
	// 1s recv timeout so Close/shutdown does not hang forever.
	tv := unix.NsecToTimeval(int64(time.Second))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &linuxHandle{fd: fd, buf: make([]byte, snaplen), iface: iface}, nil
}

func Supported() bool { return true }

func (h *linuxHandle) Read() ([]byte, error) {
	n, _, err := unix.Recvfrom(h.fd, h.buf, 0)
	if err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, nil
	}
	return h.buf[:n], nil
}

func (h *linuxHandle) Close() error {
	if h.fd < 0 {
		return nil
	}
	err := unix.Close(h.fd)
	h.fd = -1
	return err
}

func (h *linuxHandle) Iface() string { return h.iface }

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
