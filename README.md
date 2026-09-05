# sniffer

Class A (OSS/MIT). **netmapd** is a LAN sniffer and mapper in Go, aimed at a Raspberry Pi Zero 2W. It watches a subnet, builds a host/service map, and POSTs batches to a Cloudflare Worker that writes **D1**.

It is a sensor, not a tap appliance. On a switched LAN you will not see other hosts’ unicast unless the Pi is on a span port, a hub, or is the gateway. Broadcast and multicast (ARP, DHCP, mDNS, SSDP) plus an active ARP/mDNS pass still map the LAN.

## What it does

| Mode | Where | What |
|---|---|---|
| Passive sniff | Linux only (`AF_PACKET`, no libpcap, no cgo) | Ethernet → ARP, IPv4/IPv6, TCP (SYN/SNI/Host), UDP (DNS/mDNS/DHCP/SSDP) |
| Active map | Every `GOOS` | ARP sweep (Linux), `/proc/net/arp`, mDNS PTR queries, reverse DNS, optional TCP probe |
| Upload | Every `GOOS` | JSON batch to `POST /v1/ingest`; local JSONL spool if `--log` is set |

`CGO_ENABLED=0`. Packet capture is behind `//go:build linux`. The mapper and uploader compile everywhere.

## Build

Go 1.25+. Do not compile on the Pi.

```sh
make test
make dist
# outputs:
#   dist/netmapd-linux-arm64     Pi Zero 2W / Pi 3+ / ARM64 boards   (GOARM64=v8.0)
#   dist/netmapd-linux-amd64     servers, x86 laptops
#   dist/netmapd.exe             Windows PCs
#   dist/netmapd-darwin-arm64    current Macs
```

Same source, four native binaries. A `linux/arm64` binary will not run on `linux/amd64`.

Original Pi Zero / Pi 1 (32-bit ARMv6) only if you still have one:

```sh
make pi-v6   # GOOS=linux GOARCH=arm GOARM=6
```

## Run

Local mapper, no capture, no cloud:

```sh
go run ./cmd/netmapd --passive=false --stdout --flush-interval 10s
```

Pi Zero 2W (64-bit Raspberry Pi OS Lite):

```sh
scp dist/netmapd-linux-arm64 pi@zero:/tmp/netmapd
ssh pi@zero
sudo git clone … /opt/sniffer   # or copy deploy/ + the binary
sudo /opt/sniffer/deploy/install.sh /tmp/netmapd
sudo $EDITOR /etc/netmapd.env   # NETMAPD_IFACE, NETMAPD_API, NETMAPD_TOKEN
sudo systemctl restart netmapd
```

The unit runs as `netmapd` with `CAP_NET_RAW` and `CAP_NET_ADMIN` (not root). Memory cap 80 MB.

Wi-Fi (`wlan0`) in managed mode will not promiscuously see other unicast. Prefer a USB Ethernet adapter, or rely on the active ARP pass.

## Worker + D1

The agent does not talk to D1 directly. It POSTs to a Worker. A complete ingest API lives in `worker/`:

```sh
cd worker
npm install
npx wrangler d1 create sniffer          # paste database_id into wrangler.jsonc
npx wrangler d1 migrations apply sniffer --local
npx wrangler d1 migrations apply sniffer --remote
npx wrangler secret put INGEST_TOKEN
npx wrangler deploy
```

| Method | Path | Auth | Role |
|---|---|---|---|
| GET | `/health` | no | liveness |
| POST | `/v1/ingest` | Bearer | upsert hosts/services/flows/names |
| POST | `/v1/heartbeat` | Bearer | sensor last-seen |
| GET | `/v1/hosts` | Bearer | recent hosts (`?sensor=`) |
| GET | `/v1/services` | Bearer | open ports |
| GET | `/v1/map` | Bearer | hosts + services + 1h flow edges |

Agent:

```sh
netmapd --api https://sniffer.<account>.workers.dev --token "$INGEST_TOKEN" --sensor-id pizero-office
```

You can replace `worker/` with your own API as long as it accepts the same JSON (`internal/obs.Batch`). Schema is `worker/migrations/0001_init.sql`.

## Flags

| Flag | Env | Default |
|---|---|---|
| `--iface` | `NETMAPD_IFACE` | first non-loopback IPv4 iface |
| `--api` | `NETMAPD_API` | empty (local only) |
| `--token` | `NETMAPD_TOKEN` | empty |
| `--sensor-id` | `NETMAPD_SENSOR_ID` | hostname |
| `--log` | `NETMAPD_LOG` | empty |
| `--passive` | | true (Linux) |
| `--active` | | true |
| `--probe` | | false (TCP-connect live hosts) |
| `--ports` | | `22,80,443` |
| `--scan-interval` | | 5m |
| `--flush-interval` | | 30s |
| `--promisc` | | true |
| `--stdout` | | false |

## Layout

```
cmd/netmapd/          agent
internal/capture/     AF_PACKET (linux) / stub
internal/decode/      Ethernet → observations (pure Go)
internal/mapper/      in-memory host/service/flow/name map
internal/scan/        ARP / mDNS / TCP / PTR
internal/upload/      Worker HTTP client
internal/oui/         short vendor table
worker/               Cloudflare Worker + D1 migrations
deploy/               systemd unit, install.sh, logrotate
```

## Limits (Pi Zero 2W)

512 MB RAM, four Cortex-A53 cores. The process keeps at most 4096 hosts, 8192 services, 8192 one-minute flow buckets, 4096 DNS names. Payloads are not stored. systemd `MemoryMax=80M`.

Only run this on networks you own or are authorized to monitor.
