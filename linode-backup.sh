#!/usr/bin/env bash
#
# linode-backup.sh — Bespoke Linode Server Backup Utility
#
# Pulls all meaningful data and configurations from a Linode server
# into a single compressed archive for local retention before deletion.
#
# Usage:
#   ./linode-backup.sh [-p port] <user@host> [ssh-key-path]
#
# Examples:
#   ./linode-backup.sh root@203.0.113.50
#   ./linode-backup.sh -p 2222 root@203.0.113.50
#   ./linode-backup.sh -p 2222 root@mylinode.example.com ~/.ssh/linode_key
#   ./linode-backup.sh deploy@203.0.113.50 ~/.ssh/id_ed25519
#
# Output:
#   ./linode-backup-<hostname>-<date>.tar.gz
#
set -euo pipefail

# ─── Color helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { printf '%b\n' "${CYAN}[INFO]${NC}  $*"; }
ok()    { printf '%b\n' "${GREEN}[OK]${NC}    $*"; }
warn()  { printf '%b\n' "${YELLOW}[WARN]${NC}  $*"; }
err()   { printf '%b\n' "${RED}[ERR]${NC}   $*" >&2; }
header(){ printf '\n%b\n' "${BOLD}━━━ $* ━━━${NC}"; }

# ─── Args & validation ───────────────────────────────────────────────────────
SSH_PORT="22"

while getopts "p:" opt; do
    case $opt in
        p) SSH_PORT="$OPTARG" ;;
        *) printf '%b\n' "${BOLD}Usage:${NC} $0 [-p port] <user@host> [ssh-key-path]"; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if [[ $# -lt 1 ]]; then
    printf '%b\n' "${BOLD}Usage:${NC} $0 [-p port] <user@host> [ssh-key-path]"
    echo ""
    echo "  -p port        SSH port (default: 22)"
    echo "  user@host      SSH target (e.g., root@203.0.113.50)"
    echo "  ssh-key-path   Optional path to SSH private key"
    exit 1
fi

SSH_TARGET="$1"
SSH_KEY="${2:-}"

SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o BatchMode=yes -p $SSH_PORT"
SCP_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o BatchMode=yes -P $SSH_PORT"
if [[ -n "$SSH_KEY" ]]; then
    SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
    SCP_OPTS="$SCP_OPTS -i $SSH_KEY"
fi

# Build the ssh/scp command arrays
ssh_cmd() { ssh $SSH_OPTS "$SSH_TARGET" "$@"; }
scp_cmd() { scp $SCP_OPTS "$@"; }

# ─── Connectivity check ──────────────────────────────────────────────────────
info "Testing SSH connectivity to ${BOLD}$SSH_TARGET${NC} (port $SSH_PORT) ..."
if ! ssh_cmd "echo ok" &>/dev/null; then
    err "Cannot connect to $SSH_TARGET — check your credentials and host."
    exit 1
fi
ok "Connected."

REMOTE_HOSTNAME=$(ssh_cmd "hostname -s" 2>/dev/null || echo "linode")
REMOTE_USER=$(echo "$SSH_TARGET" | cut -d@ -f1)
DATE_STAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVE_NAME="linode-backup-${REMOTE_HOSTNAME}-${DATE_STAMP}"
REMOTE_STAGING="/tmp/${ARCHIVE_NAME}"

info "Remote hostname: ${BOLD}$REMOTE_HOSTNAME${NC}"
info "Remote staging:  $REMOTE_STAGING"

# ─── Remote backup script ────────────────────────────────────────────────────
# We generate a self-contained script, push it to the remote, and execute it.
# This avoids hundreds of individual SSH round-trips.

REMOTE_SCRIPT=$(cat <<'REMOTE_EOF'
#!/usr/bin/env bash
set -uo pipefail

STAGING="__STAGING__"
mkdir -p "$STAGING"

log()  { echo "[REMOTE]  $*"; }
grab() {
    # grab <label> <source-path> [<dest-subdir>]
    local label="$1" src="$2" dest="${3:-}"
    local target="$STAGING/${dest:-$label}"
    if [[ -e "$src" ]]; then
        mkdir -p "$target"
        cp -a "$src" "$target/" 2>/dev/null && log "✓ $label" || log "⚠ $label (partial)"
    else
        log "– $label (not present, skipping)"
    fi
}

grab_glob() {
    # grab_glob <label> <parent-dir> <glob-pattern> [<dest-subdir>]
    local label="$1" parent="$2" pattern="$3" dest="${4:-$label}"
    local target="$STAGING/$dest"
    local found=0
    mkdir -p "$target"
    for f in "$parent"/$pattern; do
        [[ -e "$f" ]] || continue
        cp -a "$f" "$target/" 2>/dev/null
        found=1
    done
    if [[ $found -eq 1 ]]; then
        log "✓ $label"
    else
        log "– $label (none found, skipping)"
    fi
}

dump_cmd() {
    # dump_cmd <label> <output-file> <command...>
    local label="$1" outfile="$STAGING/$2"; shift 2
    if command -v "${1}" &>/dev/null; then
        "$@" > "$outfile" 2>/dev/null && log "✓ $label" || log "⚠ $label (partial)"
    else
        log "– $label ($1 not found, skipping)"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. SYSTEM METADATA
# ══════════════════════════════════════════════════════════════════════════════
log "── System metadata ──"
mkdir -p "$STAGING/system"

{
    echo "=== Backup Timestamp ==="
    date -u +"%Y-%m-%dT%H:%M:%SZ"
    echo ""
    echo "=== Hostname ==="
    hostname -f 2>/dev/null || hostname
    echo ""
    echo "=== OS Release ==="
    cat /etc/os-release 2>/dev/null
    echo ""
    echo "=== Kernel ==="
    uname -a
    echo ""
    echo "=== Uptime ==="
    uptime
    echo ""
    echo "=== Disk Usage ==="
    df -h
    echo ""
    echo "=== Memory ==="
    free -h
    echo ""
    echo "=== Block Devices ==="
    lsblk 2>/dev/null || true
    echo ""
    echo "=== IP Addresses ==="
    ip -br addr 2>/dev/null || ifconfig 2>/dev/null || true
    echo ""
    echo "=== Listening Ports ==="
    ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true
    echo ""
    echo "=== Running Services ==="
    systemctl list-units --type=service --state=running 2>/dev/null || true
} > "$STAGING/system/system-info.txt"
log "✓ System info snapshot"

# ══════════════════════════════════════════════════════════════════════════════
# 2. SYSTEM CONFIGURATION (/etc)
# ══════════════════════════════════════════════════════════════════════════════
log "── System configuration ──"
mkdir -p "$STAGING/etc-full"
# Full /etc backup (configs are small, just grab everything)
cp -a /etc "$STAGING/etc-full/" 2>/dev/null && log "✓ /etc (full copy)" || log "⚠ /etc (partial)"

# ══════════════════════════════════════════════════════════════════════════════
# 3. PACKAGE LISTS
# ══════════════════════════════════════════════════════════════════════════════
log "── Installed packages ──"
mkdir -p "$STAGING/packages"
dump_cmd "dpkg packages"     "packages/dpkg-list.txt"      dpkg --get-selections
dump_cmd "apt packages"      "packages/apt-installed.txt"   apt list --installed
dump_cmd "rpm packages"      "packages/rpm-list.txt"        rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'
dump_cmd "dnf packages"      "packages/dnf-installed.txt"   dnf list installed
dump_cmd "pip packages"      "packages/pip-freeze.txt"      pip freeze
dump_cmd "pip3 packages"     "packages/pip3-freeze.txt"     pip3 freeze
dump_cmd "npm global pkgs"   "packages/npm-global.txt"      npm list -g --depth=0
dump_cmd "snap packages"     "packages/snap-list.txt"       snap list
dump_cmd "flatpak packages"  "packages/flatpak-list.txt"    flatpak list

# ══════════════════════════════════════════════════════════════════════════════
# 4. USER DATA & HOME DIRECTORIES
# ══════════════════════════════════════════════════════════════════════════════
log "── User data ──"
mkdir -p "$STAGING/home"

# Copy home dirs (skip huge caches but keep dotfiles/configs)
for homedir in /home/* /root; do
    [[ -d "$homedir" ]] || continue
    user=$(basename "$homedir")
    dest="$STAGING/home/$user"
    mkdir -p "$dest"

    # Use rsync if available for selective copy, otherwise cp
    if command -v rsync &>/dev/null; then
        rsync -a \
            --exclude='.cache' \
            --exclude='.local/share/Trash' \
            --exclude='node_modules' \
            --exclude='.npm/_cacache' \
            --exclude='__pycache__' \
            --exclude='.venv' \
            --exclude='venv' \
            --exclude='.cargo/registry' \
            --exclude='.rustup' \
            --exclude='go/pkg' \
            "$homedir/" "$dest/" 2>/dev/null
    else
        cp -a "$homedir" "$STAGING/home/" 2>/dev/null
    fi
    log "✓ Home: $homedir"
done

# ══════════════════════════════════════════════════════════════════════════════
# 5. CRONTABS
# ══════════════════════════════════════════════════════════════════════════════
log "── Crontabs ──"
mkdir -p "$STAGING/cron"
grab "cron.d"       /etc/cron.d        "cron"
grab "cron.daily"   /etc/cron.daily    "cron"
grab "cron.hourly"  /etc/cron.hourly   "cron"
grab "cron.weekly"  /etc/cron.weekly   "cron"
grab "cron.monthly" /etc/cron.monthly  "cron"
[[ -f /etc/crontab ]] && cp /etc/crontab "$STAGING/cron/system-crontab" 2>/dev/null

# Per-user crontabs
if [[ -d /var/spool/cron/crontabs ]]; then
    cp -a /var/spool/cron/crontabs "$STAGING/cron/user-crontabs" 2>/dev/null && log "✓ User crontabs"
elif [[ -d /var/spool/cron ]]; then
    cp -a /var/spool/cron "$STAGING/cron/user-crontabs" 2>/dev/null && log "✓ User crontabs"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 6. SYSTEMD CUSTOM UNITS
# ══════════════════════════════════════════════════════════════════════════════
log "── Systemd units ──"
mkdir -p "$STAGING/systemd"
grab "system units"  /etc/systemd/system  "systemd"
# Also list enabled units
systemctl list-unit-files --state=enabled 2>/dev/null > "$STAGING/systemd/enabled-units.txt" || true
log "✓ Enabled unit list"

# ══════════════════════════════════════════════════════════════════════════════
# 7. WEB SERVERS
# ══════════════════════════════════════════════════════════════════════════════
log "── Web server configs ──"
grab "nginx-conf"     /etc/nginx            "webserver"
grab "apache2-conf"   /etc/apache2          "webserver"
grab "httpd-conf"     /etc/httpd            "webserver"
grab "caddy-conf"     /etc/caddy            "webserver"
[[ -f /etc/Caddyfile ]] && cp /etc/Caddyfile "$STAGING/webserver/" 2>/dev/null

# Web roots (common locations)
log "── Web roots ──"
for webroot in /var/www /srv/www /usr/share/nginx/html; do
    if [[ -d "$webroot" ]]; then
        mkdir -p "$STAGING/web-data"
        if command -v rsync &>/dev/null; then
            rsync -a --exclude='node_modules' --exclude='.git' \
                "$webroot/" "$STAGING/web-data/$(basename $webroot)/" 2>/dev/null
        else
            cp -a "$webroot" "$STAGING/web-data/" 2>/dev/null
        fi
        log "✓ Web root: $webroot"
    fi
done

# ══════════════════════════════════════════════════════════════════════════════
# 8. SSL/TLS CERTIFICATES
# ══════════════════════════════════════════════════════════════════════════════
log "── SSL/TLS certificates ──"
grab "letsencrypt"    /etc/letsencrypt     "ssl"
grab "ssl-certs"      /etc/ssl             "ssl"
grab "pki"            /etc/pki             "ssl"

# ══════════════════════════════════════════════════════════════════════════════
# 9. DATABASES
# ══════════════════════════════════════════════════════════════════════════════
log "── Database dumps ──"
mkdir -p "$STAGING/databases"

# MySQL / MariaDB
if command -v mysqldump &>/dev/null; then
    # Try direct first, then sudo root (for unix socket auth), then give up
    if mysqldump --all-databases --single-transaction --routines --triggers \
        > "$STAGING/databases/mysql-all-databases.sql" 2>/dev/null; then
        log "✓ MySQL/MariaDB dump (all databases)"
    elif sudo mysqldump -u root --all-databases --single-transaction --routines --triggers \
        > "$STAGING/databases/mysql-all-databases.sql" 2>/dev/null; then
        log "✓ MySQL/MariaDB dump (all databases, via sudo)"
    else
        log "⚠ MySQL/MariaDB: could not dump (auth required — add credentials to ~/.my.cnf)"
        rm -f "$STAGING/databases/mysql-all-databases.sql"
    fi
fi

# PostgreSQL
if command -v pg_dumpall &>/dev/null; then
    if sudo -u postgres pg_dumpall > "$STAGING/databases/postgres-all.sql" 2>/dev/null; then
        log "✓ PostgreSQL dump (all databases)"
    else
        log "⚠ PostgreSQL: could not dump (check permissions)"
        rm -f "$STAGING/databases/postgres-all.sql"
    fi
fi

# PostgreSQL configs
grab "postgresql-conf" /etc/postgresql "databases"

# MongoDB
if command -v mongodump &>/dev/null; then
    if mongodump --out="$STAGING/databases/mongodb-dump" 2>/dev/null; then
        log "✓ MongoDB dump"
    else
        log "⚠ MongoDB: could not dump (auth required)"
        rm -rf "$STAGING/databases/mongodb-dump"
    fi
fi

# Redis
if command -v redis-cli &>/dev/null; then
    # Trigger save and copy the dump file
    redis-cli BGSAVE &>/dev/null && sleep 2
    REDIS_DIR=$(redis-cli CONFIG GET dir 2>/dev/null | tail -1)
    REDIS_FILE=$(redis-cli CONFIG GET dbfilename 2>/dev/null | tail -1)
    if [[ -n "$REDIS_DIR" && -n "$REDIS_FILE" && -f "$REDIS_DIR/$REDIS_FILE" ]]; then
        cp "$REDIS_DIR/$REDIS_FILE" "$STAGING/databases/redis-dump.rdb" 2>/dev/null
        log "✓ Redis dump"
    else
        log "– Redis: no dump file found"
    fi
fi

# SQLite — find any .db/.sqlite/.sqlite3 files in common locations
find /var /opt /srv /home -maxdepth 4 \
    \( -name "*.sqlite" -o -name "*.sqlite3" -o -name "*.db" \) \
    -size +0c -size -500M \
    2>/dev/null | head -50 | while read -r dbfile; do
    dest="$STAGING/databases/sqlite/$(dirname "$dbfile" | tr '/' '_')"
    mkdir -p "$dest"
    cp "$dbfile" "$dest/" 2>/dev/null
done
[[ -d "$STAGING/databases/sqlite" ]] && log "✓ SQLite files" || log "– No SQLite files found"

# ══════════════════════════════════════════════════════════════════════════════
# 10. DOCKER
# ══════════════════════════════════════════════════════════════════════════════
log "── Docker ──"
if command -v docker &>/dev/null; then
    mkdir -p "$STAGING/docker"

    # Container list & inspect
    docker ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}' \
        > "$STAGING/docker/containers.txt" 2>/dev/null && log "✓ Container list"

    # Docker compose files (search common locations)
    find / -maxdepth 5 \
        \( -name "docker-compose.yml" -o -name "docker-compose.yaml" -o -name "compose.yml" -o -name "compose.yaml" \) \
        2>/dev/null | while read -r composefile; do
        dest="$STAGING/docker/compose-files/$(dirname "$composefile" | tr '/' '_')"
        mkdir -p "$dest"
        # Grab the compose file and any .env alongside it
        cp "$composefile" "$dest/" 2>/dev/null
        dir=$(dirname "$composefile")
        [[ -f "$dir/.env" ]] && cp "$dir/.env" "$dest/" 2>/dev/null
        [[ -f "$dir/Dockerfile" ]] && cp "$dir/Dockerfile" "$dest/" 2>/dev/null
    done
    log "✓ Docker compose files"

    # Docker daemon config
    [[ -f /etc/docker/daemon.json ]] && cp /etc/docker/daemon.json "$STAGING/docker/" 2>/dev/null

    # Volume list
    docker volume ls > "$STAGING/docker/volumes.txt" 2>/dev/null

    # Export named volume data
    for vol in $(docker volume ls -q 2>/dev/null); do
        docker run --rm -v "$vol":/volume -v "$STAGING/docker/volume-data":/backup \
            alpine tar czf "/backup/${vol}.tar.gz" -C /volume . 2>/dev/null && \
            log "✓ Docker volume: $vol" || \
            log "⚠ Docker volume: $vol (could not export)"
    done

    # Image list
    docker images --format '{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}' \
        > "$STAGING/docker/images.txt" 2>/dev/null

    # Network list
    docker network ls > "$STAGING/docker/networks.txt" 2>/dev/null
else
    log "– Docker not installed"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 11. FIREWALL RULES
# ══════════════════════════════════════════════════════════════════════════════
log "── Firewall rules ──"
mkdir -p "$STAGING/firewall"
dump_cmd "iptables v4"  "firewall/iptables-v4.rules"   iptables-save
dump_cmd "iptables v6"  "firewall/iptables-v6.rules"   ip6tables-save
dump_cmd "nftables"     "firewall/nftables.conf"        nft list ruleset
dump_cmd "ufw status"   "firewall/ufw-status.txt"       ufw status verbose
dump_cmd "firewalld"    "firewall/firewalld-zones.txt"  firewall-cmd --list-all-zones

# ══════════════════════════════════════════════════════════════════════════════
# 12. APPLICATION CONFIGS & DATA (/opt, /srv, /var/lib)
# ══════════════════════════════════════════════════════════════════════════════
log "── Application data ──"

# /opt (commonly used for self-hosted apps)
if [[ -d /opt ]] && [[ "$(ls -A /opt 2>/dev/null)" ]]; then
    mkdir -p "$STAGING/app-data"
    if command -v rsync &>/dev/null; then
        rsync -a --exclude='node_modules' --exclude='.git' --exclude='__pycache__' \
            --exclude='.venv' --exclude='venv' --exclude='*.log' \
            --max-size=100M \
            /opt/ "$STAGING/app-data/opt/" 2>/dev/null
    else
        cp -a /opt "$STAGING/app-data/" 2>/dev/null
    fi
    log "✓ /opt data"
fi

# /srv (another common app root)
if [[ -d /srv ]] && [[ "$(ls -A /srv 2>/dev/null)" ]]; then
    mkdir -p "$STAGING/app-data"
    if command -v rsync &>/dev/null; then
        rsync -a --exclude='node_modules' --exclude='.git' --exclude='__pycache__' \
            --max-size=100M \
            /srv/ "$STAGING/app-data/srv/" 2>/dev/null
    else
        cp -a /srv "$STAGING/app-data/" 2>/dev/null
    fi
    log "✓ /srv data"
fi

# ══════════════════════════════════════════════════════════════════════════════
# 13. LOGS (recent, compressed — last 7 days only)
# ══════════════════════════════════════════════════════════════════════════════
log "── Recent logs ──"
mkdir -p "$STAGING/logs"

# Grab journald logs from the last 7 days
if command -v journalctl &>/dev/null; then
    journalctl --since "7 days ago" --no-pager > "$STAGING/logs/journal-7d.txt" 2>/dev/null
    log "✓ Journal logs (7 days)"
fi

# Key log files (just tail the last 10k lines to keep it reasonable)
for logfile in /var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure \
               /var/log/nginx/access.log /var/log/nginx/error.log \
               /var/log/apache2/access.log /var/log/apache2/error.log; do
    if [[ -f "$logfile" ]]; then
        dest="$STAGING/logs/$(basename "$logfile")"
        tail -n 10000 "$logfile" > "$dest" 2>/dev/null
    fi
done
log "✓ Key log tails"

# ══════════════════════════════════════════════════════════════════════════════
# 14. MISCELLANEOUS
# ══════════════════════════════════════════════════════════════════════════════
log "── Misc ──"
mkdir -p "$STAGING/misc"

# fstab / mounts
cp /etc/fstab "$STAGING/misc/" 2>/dev/null
mount > "$STAGING/misc/mounts.txt" 2>/dev/null

# SSH host keys (useful if you want to preserve host identity)
mkdir -p "$STAGING/misc/ssh-host-keys"
cp /etc/ssh/ssh_host_* "$STAGING/misc/ssh-host-keys/" 2>/dev/null && log "✓ SSH host keys"

# Fail2ban
grab "fail2ban" /etc/fail2ban "misc"

# Supervisor
grab "supervisor" /etc/supervisor "misc"

# PM2 (Node.js process manager)
if command -v pm2 &>/dev/null; then
    pm2 save 2>/dev/null
    pm2 list > "$STAGING/misc/pm2-list.txt" 2>/dev/null && log "✓ PM2 process list"
    [[ -f ~/.pm2/dump.pm2 ]] && cp ~/.pm2/dump.pm2 "$STAGING/misc/" 2>/dev/null
fi

# Environment files in common locations
find /etc /opt /srv /var/www -maxdepth 3 -name ".env" -o -name ".env.*" 2>/dev/null | \
    while read -r envfile; do
        dest="$STAGING/misc/env-files/$(dirname "$envfile" | tr '/' '_')"
        mkdir -p "$dest"
        cp "$envfile" "$dest/" 2>/dev/null
    done
log "✓ Environment files"

# ══════════════════════════════════════════════════════════════════════════════
# 15. CREATE MANIFEST
# ══════════════════════════════════════════════════════════════════════════════
log "── Creating manifest ──"
{
    echo "LINODE BACKUP MANIFEST"
    echo "======================"
    echo "Hostname:   $(hostname -f 2>/dev/null || hostname)"
    echo "Date:       $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Backup by:  linode-backup.sh"
    echo ""
    echo "CONTENTS:"
    echo "---------"
    find "$STAGING" -type f | sed "s|$STAGING/||" | sort
    echo ""
    echo "SIZE SUMMARY:"
    echo "-------------"
    du -sh "$STAGING"/* 2>/dev/null | sed "s|$STAGING/||"
    echo ""
    echo "TOTAL:"
    du -sh "$STAGING" 2>/dev/null
} > "$STAGING/MANIFEST.txt"
log "✓ Manifest written"

# ══════════════════════════════════════════════════════════════════════════════
# 16. COMPRESS
# ══════════════════════════════════════════════════════════════════════════════
log "── Compressing archive ──"
ARCHIVE_PATH="/tmp/$(basename "$STAGING").tar.gz"
tar czf "$ARCHIVE_PATH" -C /tmp "$(basename "$STAGING")" 2>/dev/null
ARCHIVE_SIZE=$(du -sh "$ARCHIVE_PATH" | cut -f1)
log "✓ Archive created: $ARCHIVE_PATH ($ARCHIVE_SIZE)"

# Clean up staging
rm -rf "$STAGING"

echo ""
echo "ARCHIVE_READY:$ARCHIVE_PATH"
REMOTE_EOF
)

# Substitute the staging path
REMOTE_SCRIPT="${REMOTE_SCRIPT//__STAGING__/$REMOTE_STAGING}"

# ─── Execute remote backup ───────────────────────────────────────────────────
header "Running backup on remote server"
info "This may take several minutes depending on data volume..."
echo ""

# Push script and execute
REMOTE_SCRIPT_PATH="/tmp/linode-backup-runner.sh"
echo "$REMOTE_SCRIPT" | ssh_cmd "cat > $REMOTE_SCRIPT_PATH && chmod +x $REMOTE_SCRIPT_PATH"

# Run and capture output, looking for the archive path
RESULT_FILE=$(mktemp)
ssh_cmd "bash $REMOTE_SCRIPT_PATH" 2>&1 | while IFS= read -r line; do
    if [[ "$line" == ARCHIVE_READY:* ]]; then
        echo "${line#ARCHIVE_READY:}" > "$RESULT_FILE"
    else
        echo "  $line"
    fi
done
ARCHIVE_REMOTE_PATH=$(cat "$RESULT_FILE" 2>/dev/null)
rm -f "$RESULT_FILE"

# Clean up remote script
ssh_cmd "rm -f $REMOTE_SCRIPT_PATH" 2>/dev/null

if [[ -z "$ARCHIVE_REMOTE_PATH" ]]; then
    err "Backup script did not produce an archive. Check the output above."
    exit 1
fi

# ─── Download archive ────────────────────────────────────────────────────────
header "Downloading archive"
LOCAL_ARCHIVE="./${ARCHIVE_NAME}.tar.gz"
info "Pulling $ARCHIVE_REMOTE_PATH → $LOCAL_ARCHIVE"

scp_cmd "$SSH_TARGET:$ARCHIVE_REMOTE_PATH" "$LOCAL_ARCHIVE"

# Clean up remote archive
ssh_cmd "rm -f $ARCHIVE_REMOTE_PATH" 2>/dev/null

LOCAL_SIZE=$(du -sh "$LOCAL_ARCHIVE" | cut -f1)

# ─── Summary ─────────────────────────────────────────────────────────────────
header "Backup complete"
echo ""
printf '%b\n' "  ${GREEN}Archive:${NC}  $LOCAL_ARCHIVE"
printf '%b\n' "  ${GREEN}Size:${NC}     $LOCAL_SIZE"
echo ""
printf '%b\n' "  ${BOLD}Extract with:${NC}"
printf '%b\n' "    tar xzf $LOCAL_ARCHIVE"
echo ""
printf '%b\n' "  ${BOLD}Contents:${NC}"
printf '%b\n' "    system/          → System info snapshot"
printf '%b\n' "    etc-full/        → Complete /etc configuration"
printf '%b\n' "    packages/        → Installed package lists"
printf '%b\n' "    home/            → User home directories"
printf '%b\n' "    cron/            → Crontabs and scheduled jobs"
printf '%b\n' "    systemd/         → Custom systemd units"
printf '%b\n' "    webserver/       → Nginx/Apache/Caddy configs"
printf '%b\n' "    web-data/        → Web root content"
printf '%b\n' "    ssl/             → TLS certificates (Let's Encrypt, etc.)"
printf '%b\n' "    databases/       → Database dumps (MySQL, Postgres, etc.)"
printf '%b\n' "    docker/          → Compose files, volumes, container info"
printf '%b\n' "    firewall/        → iptables/nft/ufw rules"
printf '%b\n' "    app-data/        → /opt and /srv application data"
printf '%b\n' "    logs/            → Recent log files (7 days)"
printf '%b\n' "    misc/            → SSH keys, .env files, fail2ban, etc."
printf '%b\n' "    MANIFEST.txt     → Full file listing and sizes"
echo ""
printf '%b\n' "  ${YELLOW}⚠ Review the archive for any secrets/credentials before"
printf '%b\n' "    storing it long-term. Consider encrypting with:${NC}"
printf '%b\n' "    gpg -c $LOCAL_ARCHIVE"
echo ""
