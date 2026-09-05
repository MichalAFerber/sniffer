#!/bin/sh
# Install netmapd on a Raspberry Pi (or any systemd Linux). Run as root:
#
#   sudo ./deploy/install.sh /path/to/netmapd-linux-arm64
set -eu

# Derive the default from THIS machine's architecture. The previous default was
# ./dist/netmapd-linux-arm64 unconditionally, which places a binary that cannot
# execute on any 32-bit Pi -- and every host this is deployed to today is armv7l.
# A wrong binary fails at exec time inside systemd, where it reads as a unit that
# will not start rather than as a build-target mistake.
ARCH=$(uname -m)
if [ $# -ge 1 ]; then
    BIN_SRC=$1
else
    case "$ARCH" in
    aarch64 | arm64) BIN_SRC=./dist/netmapd-linux-arm64 ;;
    armv7l) BIN_SRC=./dist/netmapd-linux-armv7 ;;
    armv6l) BIN_SRC=./dist/netmapd-linux-armv6 ;;
    x86_64 | amd64) BIN_SRC=./dist/netmapd-linux-amd64 ;;
    *)
        echo "$0: unrecognised architecture '$ARCH'" >&2
        echo "  pass the binary explicitly: $0 /path/to/netmapd-binary" >&2
        exit 1
        ;;
    esac
fi

if [ ! -x "$BIN_SRC" ] && [ ! -f "$BIN_SRC" ]; then
    echo "usage: $0 /path/to/netmapd-binary" >&2
    echo "missing: $BIN_SRC (derived from arch '$ARCH')" >&2
    echo "  build it with: make linux-armv7   # or the target matching this host" >&2
    exit 1
fi

# Refuse a binary that cannot run here, rather than installing it and leaving
# systemd to report a unit that will not start. An arch mismatch is the likely
# cause and the exec error does not say so.
exec_err=$({ "$BIN_SRC" --help >/dev/null; } 2>&1) || true
case "$exec_err" in
*"format error"* | *"Exec format"* | *"cannot execute"*)
    echo "$0: $BIN_SRC will not execute on this machine ($ARCH)" >&2
    echo "  almost certainly built for the wrong architecture" >&2
    exit 1
    ;;
esac

id netmapd >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin netmapd
install -d -o netmapd -g netmapd -m 0750 /var/log/netmapd
if [ ! -f /etc/netmapd.env ]; then
    cat > /etc/netmapd.env <<'EOF'
NETMAPD_IFACE=wlan0
NETMAPD_API=
NETMAPD_TOKEN=
NETMAPD_SENSOR_ID=
# Extra flags, e.g. --probe --ports 22,80,443,445
NETMAPD_ARGS=
EOF
    chmod 0640 /etc/netmapd.env
    chown root:netmapd /etc/netmapd.env
fi
install -m 0755 "$BIN_SRC" /usr/local/bin/netmapd
install -m 0644 deploy/netmapd.service /etc/systemd/system/netmapd.service
install -m 0644 deploy/logrotate /etc/logrotate.d/netmapd

if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=+ep /usr/local/bin/netmapd || true
fi

systemctl daemon-reload
systemctl enable netmapd.service
systemctl restart netmapd.service
systemctl --no-pager --full status netmapd.service || true

echo
echo "netmapd installed. Edit /etc/netmapd.env then: systemctl restart netmapd"
echo "Logs: /var/log/netmapd/events.jsonl"
echo "Wi-Fi in managed mode will not see other unicast; ARP/mDNS still map the LAN."
