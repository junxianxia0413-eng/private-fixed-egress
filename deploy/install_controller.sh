#!/usr/bin/env bash
# Bootstrap a dedicated Debian 12 Controller. No Gateway/ISP changes.
set -Eeuo pipefail
umask 027

die() { printf '%s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Run as root on the target Controller VPS.'
[[ $# -eq 1 ]] || die 'Usage: bash deploy/install_controller.sh <public-hostname-or-IPv4>'
domain=$1
# shellcheck source=/dev/null
source /etc/os-release
[[ $ID == debian && $VERSION_ID == 12 ]] || die 'Only Debian 12 is supported.'
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
target_kind=$(python3 "$source_dir/scripts/deployment.py" validate "$domain")
revision=$(git -c safe.directory="$source_dir" -C "$source_dir" rev-parse HEAD)
git -c safe.directory="$source_dir" -C "$source_dir" diff --quiet HEAD -- controller scripts deploy requirements.txt \
    || die 'Commit or discard source edits before installing a recorded release.'
app_dir=/opt/private-fixed-egress
data_dir=/var/lib/private-fixed-egress
config_dir=/etc/private-fixed-egress
marker='# Managed by Private Fixed-Egress Network Manager'

# Refuse to overwrite another application's existing reverse proxy.
if [[ -f /etc/caddy/Caddyfile ]] && ! grep -Fqx "$marker" /etc/caddy/Caddyfile; then
    die 'Existing unmanaged Caddyfile found. Review deploy/README.md before integrating.'
fi
# This bootstrap is not an unattended code upgrade mechanism.
if [[ -f $app_dir/.installed-revision ]]; then
    [[ $(cat "$app_dir/.installed-revision") == "$revision" ]] || die 'Different release installed: follow the backed-up upgrade procedure in deploy/README.md.'
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv rsync curl gnupg ca-certificates debian-keyring debian-archive-keyring apt-transport-https
# Debian 12's default Caddy predates publicly trusted IP certificates.
if [[ $target_kind == ipv4 ]]; then
    curl --fail --silent --show-error --location https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
        | gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl --fail --silent --show-error --location https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
        -o /etc/apt/sources.list.d/caddy-stable.list
    chmod 0644 /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
    apt-get update
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y caddy
if [[ $target_kind == ipv4 ]]; then
    installed_caddy=$(dpkg-query -W -f='${Version}' caddy)
    dpkg --compare-versions "$installed_caddy" ge 2.11.0 || die 'IP certificates require Caddy 2.11 or newer.'
fi
id pfem >/dev/null 2>&1 || useradd --system --home-dir "$data_dir" --shell /usr/sbin/nologin pfem
install -d -m 0755 "$app_dir"
install -d -m 0700 -o pfem -g pfem "$data_dir" "$data_dir/backups" "$data_dir/secrets"
install -d -m 0750 -o root -g pfem "$config_dir"

if [[ $source_dir != "$app_dir" ]]; then
    rsync -a --exclude='__pycache__' --exclude='*.pyc' "$source_dir/controller" "$source_dir/scripts" "$source_dir/deploy" "$app_dir/"
    install -m 0644 "$source_dir/requirements.txt" "$app_dir/requirements.txt"
fi
chown -R root:root "$app_dir/controller" "$app_dir/scripts" "$app_dir/deploy"
chmod -R u=rwX,go=rX "$app_dir/controller" "$app_dir/scripts" "$app_dir/deploy"
python3 -m venv "$app_dir/.venv"
"$app_dir/.venv/bin/python" -m pip install --disable-pip-version-check -r "$app_dir/requirements.txt"
"$app_dir/.venv/bin/python" -m pip check
chmod -R u=rwX,go=rX "$app_dir/.venv"

candidate=$(mktemp)
trap 'rm -f -- "$candidate"' EXIT
cat > "$candidate" <<EOF
APP_ENV=production
PUBLIC_URL=https://$domain
DATABASE_PATH=$data_dir/controller.db
SESSION_HOURS=8
EOF
if [[ -f $config_dir/controller.env ]]; then
    cmp -s "$candidate" "$config_dir/controller.env" || die 'Existing configuration differs; review it explicitly before reinstalling.'
else
    install -m 0640 -o root -g pfem "$candidate" "$config_dir/controller.env"
fi

cd "$app_dir"
setup_args=(--no-env)
if [[ -n ${PFEM_ADMIN_PASSWORD_FILE:-} ]]; then
    install -m 0600 -o pfem -g pfem "$PFEM_ADMIN_PASSWORD_FILE" "$data_dir/secrets/bootstrap-password"
    setup_args+=(--username "${PFEM_ADMIN_USERNAME:-admin}" --password-file "$data_dir/secrets/bootstrap-password")
fi
runuser -u pfem -- env APP_ENV=production PUBLIC_URL="https://$domain" \
    DATABASE_PATH="$data_dir/controller.db" PYTHONDONTWRITEBYTECODE=1 \
    "$app_dir/.venv/bin/python" -m scripts.setup "${setup_args[@]}"
if [[ -n ${PFEM_ADMIN_PASSWORD_FILE:-} ]]; then
    rm -f -- "$data_dir/secrets/bootstrap-password"
fi

install -m 0644 "$app_dir/deploy/controller.service" /etc/systemd/system/private-fixed-egress.service
systemctl daemon-reload
systemctl enable --now private-fixed-egress
systemctl restart private-fixed-egress
# Local probe supplies the canonical host and trusted proxy scheme.
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 \
    -H "Host: $domain" -H 'X-Forwarded-Proto: https' http://127.0.0.1:8000/healthz

python3 "$app_dir/scripts/deployment.py" caddy "$domain" > "$candidate"
caddy validate --config "$candidate" --adapter caddyfile
backup_config="/etc/caddy/Caddyfile.before-pfem-$(date -u +%Y%m%dT%H%M%S)"
cp -p /etc/caddy/Caddyfile "$backup_config"
install -m 0644 "$candidate" /etc/caddy/Caddyfile
if ! systemctl reload-or-restart caddy; then
    cp -p "$backup_config" /etc/caddy/Caddyfile
    systemctl reload-or-restart caddy || true
    die 'Caddy reload failed; previous configuration restored.'
fi
systemctl enable caddy
printf '%s\n' "$revision" > "$app_dir/.installed-revision"
chmod 0644 "$app_dir/.installed-revision"
curl --fail --silent --show-error --retry 12 --retry-all-errors --retry-delay 5 --retry-max-time 120 --max-time 15 "https://$domain/healthz" \
    || die 'Controller is running, but public HTTPS is not verified. Check target ownership, DNS (if used), ports 80/443, and Caddy logs.'
printf '\nController verified: https://%s\n' "$domain"
