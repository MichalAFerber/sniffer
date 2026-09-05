#!/bin/sh
# Install netmapd on a Raspberry Pi (or any systemd Linux). Run as root:
#
#   sudo ./deploy/install.sh /path/to/netmapd-linux-arm64
set -eu

BIN_SRC=${1:-./dist/netmapd-linux-arm64}
if [ ! -x "$BIN_SRC" ] && [ ! -f "$BIN_SRC" ]; then
    echo "usage: $0 /path/to/netmapd-binary" >&2
    echo "missing: $BIN_SRC" >&2
    exit 1
fi

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
