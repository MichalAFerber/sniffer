// Package capture is the packet-source interface. The Linux build uses
// AF_PACKET (no libpcap, no cgo). Other GOOS compile a stub so the mapper
// and uploader still build.
package capture

import "io"

// Handle yields Ethernet frames. Read returns a slice that is only valid
// until the next Read or Close.
type Handle interface {
	Read() ([]byte, error)
	Close() error
	Iface() string
}

var _ io.Closer = (Handle)(nil)
