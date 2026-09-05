package scan

import (
	"context"
	"net"
	"time"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

func arpOrNil(ctx context.Context, n TargetNet, hosts []net.IP, timeout time.Duration) []obs.Observation {
	if !ARPSupported() {
		return nil
	}
	return ARPSweep(ctx, n, hosts, timeout)
}
