# sniffer

LAN sniffer + mapper (`netmapd`) for a Pi Zero 2W. Class A (OSS/MIT). Pure Go, `CGO_ENABLED=0`. Capture is Linux `AF_PACKET` only; mapper/uploader are portable. Batches go to a Cloudflare Worker → D1.

## Commands

```sh
make test
make vet
make dist          # linux/arm64 linux/amd64 windows/amd64 darwin/arm64
make pi            # linux/arm64 GOARM64=v8.0 (Zero 2W)
go run ./cmd/netmapd --passive=false --stdout --flush-interval 10s
```

Worker (optional; the Go agent only needs the HTTP contract):

```sh
cd worker
npm install
npx wrangler d1 migrations apply sniffer --local
npx wrangler dev
```

## Architecture

- `cmd/netmapd` — flags, signal, sniff loop, scan loop, flush/heartbeat.
- `internal/decode` — Ethernet/ARP/IP/TCP/UDP/DNS/DHCP/TLS-SNI/HTTP-Host/SSDP. No cgo.
- `internal/capture` — `capture_linux.go` (`AF_PACKET`) vs `capture_stub.go`.
- `internal/scan` — ARP sweep on Linux; mDNS + TCP + PTR everywhere.
- `internal/mapper` — bounded in-memory upsert; Snapshot(flush) for upload deltas.
- `internal/upload` — `POST {api}/v1/ingest` with Bearer token.
- `worker/` — D1 ingest API. Replaceable.

## Constraints (do not “improve” these away)

- `CGO_ENABLED=0`. No libpcap, no OpenSSL bindings.
- Linux-only syscalls stay behind `//go:build linux`.
- Do not store packet payloads. Observations only.
- Do not scan wider than a /22 unless `--` cap is tiny (see `hostsIn`).
- Worker never talks to the Cloudflare REST API; D1 is a binding.
- `INGEST_TOKEN` is a secret, not a wrangler `vars` value.

Cross-compile from this Mac. Target for the Zero 2W is `linux/arm64`, not `arm`/`GOARM=6` (that is the original Pi Zero).
