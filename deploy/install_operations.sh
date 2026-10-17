#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || exit 1
app=/opt/private-fixed-egress
[[ -f /etc/private-fixed-egress/controller.env ]] || exit 2
install -d -m 700 /var/backups/private-fixed-egress
for name in full-backup service-watch; do
  install -m 644 "$app/deploy/$name.service" "/etc/systemd/system/pfem-$name.service"
  install -m 644 "$app/deploy/$name.timer" "/etc/systemd/system/pfem-$name.timer"
done
install -d -m 755 /etc/systemd/system/caddy.service.d
install -m 644 "$app/deploy/caddy-recovery.conf" /etc/systemd/system/caddy.service.d/pfem-recovery.conf
systemctl daemon-reload
systemctl enable --now pfem-full-backup.timer pfem-service-watch.timer
systemctl start --no-block pfem-full-backup.service
printf '%s\n' 'Automatic service recovery and daily private backups enabled.'
