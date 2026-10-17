#!/bin/bash
set -euo pipefail
host=$(python3 ingress.py gateway.json host)
if ! command -v caddy >/dev/null || ! dpkg --compare-versions "$(dpkg-query -W -f='${Version}' caddy)" ge 2.11.0; then
  apt-get install -y --no-install-recommends gnupg debian-keyring debian-archive-keyring apt-transport-https
  curl --fail --silent --show-error --location https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
    | gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl --fail --silent --show-error --location https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    -o /etc/apt/sources.list.d/caddy-stable.list
  chmod 644 /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y --no-install-recommends caddy
fi
python3 ingress.py gateway.json config > candidate.Caddyfile
caddy validate --config candidate.Caddyfile --adapter caddyfile
previous=/etc/caddy/Caddyfile.before-gateway
if [[ -f /etc/caddy/Caddyfile ]]; then cp -p /etc/caddy/Caddyfile "$previous"; fi
install -m 644 candidate.Caddyfile /etc/caddy/Caddyfile
if ! systemctl reload-or-restart caddy; then
  if [[ -f $previous ]]; then cp -p "$previous" /etc/caddy/Caddyfile; fi
  systemctl reload-or-restart caddy || true
  exit 79
fi
install -d -m 755 /etc/systemd/system/caddy.service.d
printf '[Service]\nRestart=on-failure\nRestartSec=5s\n' > /etc/systemd/system/caddy.service.d/pfem-recovery.conf
systemctl daemon-reload
systemctl enable caddy
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  for port in 80 443 8443; do ufw allow "$port/tcp"; done
fi
for port in 443 8443; do
  curl --fail --silent --show-error --retry 10 --retry-all-errors --retry-delay 5 --retry-max-time 120 \
    --max-time 15 --output /dev/null "https://$host:$port/healthz" || exit 79
done
printf '%s\n' "$host" > /etc/pfem-gateway/https-ingress-v1
