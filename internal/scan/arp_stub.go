//go:build !linux

package scan

import (
	"context"
	"net"
	"time"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

func ARPSupported() bool { return false }

func ARPSweep(context.Context, TargetNet, []net.IP, time.Duration) []obs.Observation {
	return nil
}
