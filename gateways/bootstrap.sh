#!/bin/bash
# Inputs are fixed paths in a private temporary directory created by the SSH runner.
set -euo pipefail
umask 077
exec 9>/run/lock/pfem-gateway.lock
flock -n 9 || exit 75
[[ $(id -u) == 0 ]] || exit 71
# shellcheck disable=SC1091
source /etc/os-release
[[ $ID == debian && $VERSION_ID == 12 ]] || exit 72
[[ $(awk '/MemTotal/ {print $2}' /proc/meminfo) -ge 393216 ]] || exit 73
[[ $(df --output=avail -k / | tail -1) -ge 524288 ]] || exit 74
managed=/etc/pfem-gateway
if [[ -e $managed && ! -f $managed/managed-v1 ]]; then exit 76; fi
if [[ ! -e $managed ]]; then
  ! id proxyadmin >/dev/null 2>&1 || exit 76
  ! id pfem-proxy >/dev/null 2>&1 || exit 76
  [[ ! -e /usr/local/bin/pfem-sing-box && ! -e /etc/systemd/system/pfem-gateway.service ]] || exit 76
  if command -v nft >/dev/null && nft list table inet pfem_guard >/dev/null 2>&1; then exit 76; fi
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl nftables sudo
install -d -m 755 "$managed"
touch "$managed/managed-v1"
id proxyadmin >/dev/null 2>&1 || useradd --create-home --shell /bin/bash proxyadmin
id pfem-proxy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/pfem-gateway --shell /usr/sbin/nologin pfem-proxy
install -d -m 700 -o proxyadmin -g proxyadmin /home/proxyadmin/.ssh
install -m 600 -o proxyadmin -g proxyadmin management.pub /home/proxyadmin/.ssh/authorized_keys
install -d -m 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
recovery=$(cat recovery.pub)
grep -qxF "$recovery" /root/.ssh/authorized_keys || printf '\n%s\n' "$recovery" >> /root/.ssh/authorized_keys
case $(uname -m) in
  x86_64) arch=amd64; digest=2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63;;
  aarch64) arch=arm64; digest=04d9b40bc98dc55b6f509ce3292145c65478f65866bea64826ebb2f382385088;;
  *) exit 77;;
esac
if [[ ! -x /usr/local/bin/pfem-sing-box ]]; then
  archive="sing-box-1.14.0-linux-$arch"
  curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 --retry 2 \
    "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/$archive.tar.gz" -o core.tar.gz
  printf '%s  core.tar.gz\n' "$digest" | sha256sum --check --status
  tar -xzf core.tar.gz "$archive/sing-box"
  install -m 755 "$archive/sing-box" /usr/local/bin/pfem-sing-box
fi
/usr/local/bin/pfem-sing-box version | head -1 | grep -qx 'sing-box version 1.14.0' || exit 78
if [[ ! -f $managed/config.json ]]; then
  install -m 640 -o root -g pfem-proxy initial.json "$managed/config.json"
fi
/usr/local/bin/pfem-sing-box check -c "$managed/config.json"
install -m 755 remote_admin.py /usr/local/sbin/pfem-gateway-admin
install -m 755 remote_probe.py /usr/local/sbin/pfem-isp-probe
install -m 644 gateway.service /etc/systemd/system/pfem-gateway.service
install -d -m 750 -o pfem-proxy -g pfem-proxy /var/lib/pfem-gateway
cat > /etc/sudoers.d/pfem-gateway <<'SUDO'
proxyadmin ALL=(root) NOPASSWD: /usr/local/sbin/pfem-gateway-admin status, /usr/local/sbin/pfem-gateway-admin reconcile, /usr/local/sbin/pfem-gateway-admin restart, /usr/local/sbin/pfem-gateway-admin harden, /usr/local/sbin/pfem-gateway-admin commit-harden
SUDO
chmod 440 /etc/sudoers.d/pfem-gateway
visudo -cf /etc/sudoers.d/pfem-gateway
if [[ ! -f $managed/firewall.nft ]]; then
  proxy_uid=$(id -u pfem-proxy)
  cat > "$managed/firewall.nft" <<NFT
add table inet pfem_guard
flush table inet pfem_guard
add chain inet pfem_guard input { type filter hook input priority -10; policy accept; }
add rule inet pfem_guard input iifname != "lo" tcp dport 10810 drop
add chain inet pfem_guard output { type filter hook output priority -10; policy accept; }
add rule inet pfem_guard output meta skuid $proxy_uid ip daddr != 127.0.0.0/8 reject
add rule inet pfem_guard output meta skuid $proxy_uid ip6 daddr != ::1 reject
NFT
fi
nft -c -f "$managed/firewall.nft"
install -m 644 firewall.service /etc/systemd/system/pfem-gateway-firewall.service
systemctl daemon-reload
systemctl enable pfem-gateway-firewall.service pfem-gateway.service
systemctl restart pfem-gateway-firewall.service
systemctl start pfem-gateway.service
echo PFEM_BOOTSTRAP_OK
