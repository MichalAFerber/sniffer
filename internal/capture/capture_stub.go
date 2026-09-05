//go:build !linux

package capture

import "fmt"

func Open(iface string, snaplen int, promisc bool) (Handle, error) {
	return nil, fmt.Errorf("packet capture is Linux-only (AF_PACKET); this build is not linux (iface=%s)", iface)
}

func Supported() bool { return false }
