#!/bin/bash
# A reviewed Git revision is the release boundary. Preserve data and old code for rollback.
set -euo pipefail
umask 077
[[ $(id -u) == 0 && $# -eq 2 ]] || { echo 'Usage: sudo bash deploy/upgrade_controller.sh <old-sha> <new-sha>'; exit 1; }
old=$1
new=$2
[[ $old =~ ^[a-f0-9]{40}$ && $new =~ ^[a-f0-9]{40}$ && $old != "$new" ]] || exit 2
exec 9>/run/lock/pfem-controller-upgrade.lock
flock -n 9 || exit 3
app=/opt/private-fixed-egress
data=/var/lib/private-fixed-egress
[[ $(cat "$app/.installed-revision") == "$old" ]] || exit 4
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ $(git -C "$source_dir" rev-parse HEAD) == "$new" ]] || exit 5
git -C "$source_dir" diff --quiet HEAD -- controller scripts deploy gateways requirements.txt || exit 6
release=/opt/pfem-releases/$new
[[ ! -e $release ]] || { echo 'Release directory already exists; inspect before retrying.'; exit 7; }
install -d -m 755 /opt/pfem-releases "$release"
rsync -a --exclude='__pycache__' --exclude='*.pyc' "$source_dir/controller" "$source_dir/scripts" \
    "$source_dir/deploy" "$source_dir/gateways" "$release/"
install -m 644 "$source_dir/requirements.txt" "$release/requirements.txt"
chmod -R u=rwX,go=rX "$release"
python3 -m venv "$release/.venv"
"$release/.venv/bin/python" -m pip install --disable-pip-version-check -r "$release/requirements.txt"
"$release/.venv/bin/python" -m pip check
# The preparation umask is private; the unprivileged service needs directory traversal.
chmod -R u=rwX,go=rX "$release"
printf '%s\n' "$new" > "$release/.installed-revision"
stamp=$(date -u +%Y%m%dT%H%M%S)
snapshot=/var/backups/pfem/controller-$stamp
install -d -m 700 "$snapshot"
old_target=$(readlink -f "$app")
backup_ready=0
rollback() {
    code=$?
    trap - ERR
    if [[ $backup_ready == 1 ]]; then
        systemctl stop private-fixed-egress.service || true
        rm -f -- "$data/controller.db-wal" "$data/controller.db-shm"
        install -m 600 -o pfem -g pfem "$snapshot/controller.db" "$data/controller.db"
    fi
    if [[ -L $app || ! -e $app ]]; then
        ln -s "$old_target" /opt/.pfem-rollback-"$$"
        mv -Tf /opt/.pfem-rollback-"$$" "$app"
    fi
    systemctl start private-fixed-egress.service || true
    echo "Upgrade failed; previous code/data restored from $snapshot"
    exit "$code"
}
systemctl stop private-fixed-egress.service
trap rollback ERR
"$app/.venv/bin/python" - "$data/controller.db" "$snapshot/controller.db" <<'PY'
import sqlite3
import sys
source = sqlite3.connect(sys.argv[1])
target = None
try:
    if source.execute("SELECT name FROM sqlite_master WHERE name='gateway_jobs'").fetchone():
        if source.execute("SELECT COUNT(*) FROM gateway_jobs WHERE state IN ('QUEUED','RUNNING')").fetchone()[0]:
            raise SystemExit('Gateway tasks are pending; resume them before upgrading.')
    if source.execute("SELECT name FROM sqlite_master WHERE name='isp_jobs'").fetchone():
        if source.execute("SELECT COUNT(*) FROM isp_jobs WHERE state IN ('QUEUED','RUNNING')").fetchone()[0]:
            raise SystemExit('ISP tasks are pending; resume them before upgrading.')
    target = sqlite3.connect(sys.argv[2])
    if source.execute("SELECT name FROM sqlite_master WHERE name='exit_jobs'").fetchone():
        if source.execute("SELECT COUNT(*) FROM exit_jobs WHERE state IN ('QUEUED','RUNNING')").fetchone()[0]:
            raise SystemExit('Exit configuration tasks are pending; resume them before upgrading.')
    source.backup(target)
    assert target.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    target.execute('DELETE FROM sessions')
    target.commit()
finally:
    if target is not None:
        target.close()
    source.close()
PY
backup_ready=1
if [[ -d $data/secrets ]]; then cp -a "$data/secrets" "$snapshot/secrets"; fi
cp -a /etc/private-fixed-egress/controller.env "$snapshot/controller.env"
if [[ ! -L $app ]]; then
    old_target=/opt/pfem-releases/legacy-$old-$stamp
    mv -- "$app" "$old_target"
fi
ln -s "$release" /opt/.pfem-current-"$$"
mv -Tf /opt/.pfem-current-"$$" "$app"
runuser -u pfem -- env DATABASE_PATH="$data/controller.db" PYTHONDONTWRITEBYTECODE=1 \
    "$release/.venv/bin/python" -c "import sys; sys.path.insert(0, '$release'); from controller.config import Settings; from controller.services.database import migrate; migrate(Settings.from_env().database_path)"
systemctl start private-fixed-egress.service
# shellcheck disable=SC1091
source /etc/private-fixed-egress/controller.env
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 --max-time 5 \
    --header "Host: ${PUBLIC_URL#https://}" --header 'X-Forwarded-Proto: https' \
    http://127.0.0.1:8000/healthz | python3 -c 'import json,sys; assert json.load(sys.stdin)=={"status":"ok","component":"controller"}'
trap - ERR
echo "Release $new active; recovery snapshot: $snapshot"
