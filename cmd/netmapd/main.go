package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/MichalAFerber/sniffer/internal/capture"
	"github.com/MichalAFerber/sniffer/internal/config"
	"github.com/MichalAFerber/sniffer/internal/decode"
	"github.com/MichalAFerber/sniffer/internal/mapper"
	"github.com/MichalAFerber/sniffer/internal/obs"
	"github.com/MichalAFerber/sniffer/internal/oui"
	"github.com/MichalAFerber/sniffer/internal/scan"
	"github.com/MichalAFerber/sniffer/internal/upload"
)

var version = "0.1.0"

func main() {
	log.SetFlags(0)
	log.SetPrefix("netmapd: ")
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	cfg, err := config.Parse(args)
	if err != nil {
		return err
	}
	if cfg.OUIFile != "" {
		if err := oui.LoadFile(cfg.OUIFile); err != nil {
			return fmt.Errorf("oui-file: %w", err)
		}
	}
	host, _ := os.Hostname()
	if cfg.SensorID == "" {
		cfg.SensorID = host
	}
	if cfg.Iface == "" {
		cfg.Iface = scan.DefaultIface()
	}
	sensor := obs.Sensor{
		ID:       cfg.SensorID,
		Hostname: host,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Version:  version,
		Iface:    cfg.Iface,
	}
	mp := mapper.New()
	up := upload.New(cfg.API, cfg.Token, sensor, cfg.Log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("start id=%s os=%s/%s iface=%s capture=%v active=%v api=%s version=%s",
		sensor.ID, sensor.OS, sensor.Arch, sensor.Iface, capture.Supported() && cfg.Passive, cfg.Active, nonempty(cfg.API, "(local)"), version)

	if cfg.Passive && capture.Supported() {
		if cfg.Iface == "" {
			return fmt.Errorf("no interface to sniff; pass --iface")
		}
		h, err := capture.Open(cfg.Iface, cfg.Snaplen, cfg.Promisc)
		if err != nil {
			return err
		}
		defer h.Close()
		go sniff(ctx, h, mp, cfg.Stdout)
	} else if cfg.Passive && !capture.Supported() {
		log.Printf("passive sniff skipped: this binary is %s/%s (AF_PACKET is linux-only)", runtime.GOOS, runtime.GOARCH)
	}

	if cfg.Active {
		go activeLoop(ctx, cfg, mp, cfg.Stdout)
	}

	flush := time.NewTicker(cfg.FlushInterval)
	defer flush.Stop()
	beat := time.NewTicker(60 * time.Second)
	defer beat.Stop()

	flushOnce := func() {
		hosts, svcs, flows, names := mp.Snapshot(true)
		if err := up.Send(ctx, hosts, svcs, flows, names); err != nil {
			log.Printf("upload: %v", err)
		}
	}

	// First mapper pass immediately so a Pi that just booted still reports.
	if cfg.Active {
		ingestScan(ctx, cfg, mp, cfg.Stdout)
	}
	flushOnce()

	for {
		select {
		case <-ctx.Done():
			flushOnce()
			return nil
		case <-flush.C:
			flushOnce()
		case <-beat.C:
			h, s, f, n := mp.Counts()
			if err := up.Heartbeat(ctx, h, s, f, n); err != nil {
				log.Printf("heartbeat: %v", err)
			}
		}
	}
}

func sniff(ctx context.Context, h capture.Handle, mp *mapper.Mapper, stdout bool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		frame, err := h.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if len(frame) == 0 {
			continue
		}
		list := decode.Frame(frame)
		if len(list) == 0 {
			continue
		}
		now := time.Now().UTC()
		for i := range list {
			if list[i].Time.IsZero() {
				list[i].Time = now
			}
		}
		mp.Ingest(list)
		if stdout {
			printJSONL(list)
		}
	}
}

func activeLoop(ctx context.Context, cfg config.Config, mp *mapper.Mapper, stdout bool) {
	t := time.NewTicker(cfg.ScanInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ingestScan(ctx, cfg, mp, stdout)
		}
	}
}

func ingestScan(ctx context.Context, cfg config.Config, mp *mapper.Mapper, stdout bool) {
	opt := scan.DefaultOptions()
	opt.Iface = cfg.Iface
	opt.Ports = cfg.Ports
	opt.ProbeTCP = cfg.ProbeTCP
	list := scan.Discover(ctx, opt)
	if len(list) == 0 {
		return
	}
	mp.Ingest(list)
	if stdout {
		printJSONL(list)
	}
	log.Printf("scan: %d observations", len(list))
}

func printJSONL(list []obs.Observation) {
	enc := json.NewEncoder(os.Stdout)
	for _, o := range list {
		_ = enc.Encode(o)
	}
}

func nonempty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
