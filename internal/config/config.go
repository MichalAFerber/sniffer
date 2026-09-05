package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Iface         string
	API           string
	Token         string
	SensorID      string
	Log           string
	OUIFile       string
	Passive       bool
	Active        bool
	ProbeTCP      bool
	Promisc       bool
	Ports         []uint16
	ScanInterval  time.Duration
	FlushInterval time.Duration
	Snaplen       int
	Stdout        bool
}

func Parse(args []string) (Config, error) {
	var c Config
	fs := flag.NewFlagSet("netmapd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&c.Iface, "iface", env("NETMAPD_IFACE", ""), "interface to sniff/scan (default: first non-loopback IPv4)")
	fs.StringVar(&c.API, "api", env("NETMAPD_API", ""), "Worker base URL, e.g. https://sniffer.example.workers.dev")
	fs.StringVar(&c.Token, "token", env("NETMAPD_TOKEN", ""), "Bearer token for the Worker (or NETMAPD_TOKEN)")
	fs.StringVar(&c.SensorID, "sensor-id", env("NETMAPD_SENSOR_ID", ""), "stable sensor id (default: hostname)")
	fs.StringVar(&c.Log, "log", env("NETMAPD_LOG", ""), "JSONL spool path (written even when API is set)")
	fs.StringVar(&c.OUIFile, "oui-file", "", "optional IEEE OUI CSV to extend the built-in vendor table")
	passive := fs.Bool("passive", true, "sniff packets (Linux AF_PACKET; no-op on other OS)")
	active := fs.Bool("active", true, "ARP/mDNS/TCP mapper pass on an interval")
	fs.BoolVar(&c.ProbeTCP, "probe", false, "TCP-connect live hosts on --ports after ARP")
	fs.BoolVar(&c.Promisc, "promisc", true, "promiscuous mode (Linux; needs CAP_NET_ADMIN)")
	fs.BoolVar(&c.Stdout, "stdout", false, "print each observation as JSONL to stdout")
	ports := fs.String("ports", "22,80,443", "TCP ports for --probe")
	fs.DurationVar(&c.ScanInterval, "scan-interval", 5*time.Minute, "active mapper interval")
	fs.DurationVar(&c.FlushInterval, "flush-interval", 30*time.Second, "upload interval")
	fs.IntVar(&c.Snaplen, "snaplen", 2048, "capture snaplen")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	c.Passive = *passive
	c.Active = *active
	var err error
	c.Ports, err = parsePorts(*ports)
	if err != nil {
		return c, err
	}
	return c, nil
}

func parsePorts(s string) ([]uint16, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []uint16
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("bad port %q", p)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
