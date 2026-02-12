# linode-backup

A single-command utility that pulls all meaningful data and configurations from a Linode server into a compressed local archive — designed for use before deleting a Linode from the Akamai Cloud console.

## Why this exists

Akamai's Backups service for Linode **does not support downloading backups**. Their [official documentation](https://techdocs.akamai.com/cloud-computing/docs/download-backups-locally) confirms that backups can only be restored to another Linode — not downloaded to your local machine. Their suggested workflow is to restore a backup to a new (billable) Linode, then manually SCP files off of it.

That's fine for pulling a single config file, but if you're decommissioning a server and want a comprehensive local copy of everything — configs, databases, Docker volumes, crontabs, SSL certs, application data — you need something more thorough.

`linode-backup` handles the entire process in a single command. It SSHs into your Linode, collects everything worth keeping, compresses it into a `.tar.gz`, pulls it down locally, and cleans up after itself.

## What it captures

| Category | What's included |
|---|---|
| **System metadata** | Hostname, OS, kernel, disk usage, memory, IP addresses, listening ports, running services |
| **Full /etc** | Complete copy of `/etc` — all system-level configuration in one shot |
| **Installed packages** | Package lists from dpkg, apt, rpm, dnf, pip, pip3, npm, snap, and flatpak |
| **Home directories** | All user homes including root, with smart excludes for caches, `node_modules`, `.venv`, etc. |
| **Crontabs** | System crontab, cron.d/daily/hourly/weekly/monthly, and per-user crontabs |
| **Systemd units** | Custom unit files from `/etc/systemd/system` and a list of all enabled units |
| **Web server configs** | Nginx, Apache, Caddy configurations |
| **Web root content** | `/var/www`, `/srv/www`, and nginx default html directory |
| **SSL/TLS certificates** | Let's Encrypt, `/etc/ssl`, and `/etc/pki` |
| **Database dumps** | MySQL/MariaDB, PostgreSQL, MongoDB, Redis, and auto-discovered SQLite files |
| **Docker** | Container list, compose files with `.env`/`Dockerfile`, named volume data exports, image/network listings, daemon config |
| **Firewall rules** | iptables (v4/v6), nftables, ufw, and firewalld |
| **Application data** | `/opt` and `/srv` contents (with size limits and cache exclusions) |
| **Recent logs** | Last 7 days of journald logs plus tails of key log files (syslog, auth, nginx, apache) |
| **Miscellaneous** | SSH host keys, fstab, fail2ban config, supervisor config, PM2 state, `.env` files from common locations |

A `MANIFEST.txt` is included at the root of every archive with a full file listing and size summary.

## Installation

```bash
curl -O https://raw.githubusercontent.com/solidsystems/linode-backup/main/linode-backup.sh
chmod +x linode-backup.sh
```

Or clone the repo:

```bash
git clone https://github.com/solidsystems/linode-backup.git
cd linode-backup
chmod +x linode-backup.sh
```

No dependencies beyond a standard Unix environment with `ssh` and `scp`.

## Usage

```bash
./linode-backup.sh [-p port] <user@host> [ssh-key-path]
```

### Examples

```bash
# Basic usage
./linode-backup.sh root@203.0.113.50

# Custom SSH port
./linode-backup.sh -p 2222 root@203.0.113.50

# Custom port with a specific SSH key
./linode-backup.sh -p 2222 root@mylinode.example.com ~/.ssh/linode_key
```

### Output

The script produces a single timestamped archive in your current directory:

```
linode-backup-<hostname>-<YYYYMMDD-HHMMSS>.tar.gz
```

Extract it with:

```bash
tar xzf linode-backup-myserver-20260212-143000.tar.gz
```

## How it works

1. Tests SSH connectivity to the target server
2. Checks for passwordless sudo — if available, the entire backup runs as root for full access to all files and databases
3. Pushes a self-contained collection script to the remote host (avoids hundreds of individual SSH round-trips)
4. Executes the script remotely, streaming progress back to your terminal
5. Compresses everything into a `.tar.gz` on the remote server
6. SCPs the archive to your local machine
7. Cleans up all temporary files on the remote server

The entire process is non-destructive — it only reads from the server and writes to `/tmp` for staging.

## Archive structure

```
linode-backup-<hostname>-<date>/
├── MANIFEST.txt            # Full file listing and size summary
├── system/                 # System info snapshot
├── etc-full/               # Complete /etc copy
├── packages/               # Installed package lists
├── home/                   # User home directories
├── cron/                   # Crontabs and scheduled jobs
├── systemd/                # Custom systemd units + enabled list
├── webserver/              # Nginx/Apache/Caddy configs
├── web-data/               # Web root content
├── ssl/                    # TLS certificates
├── databases/              # Database dumps
├── docker/                 # Compose files, volumes, container info
├── firewall/               # Firewall rules
├── app-data/               # /opt and /srv application data
├── logs/                   # Recent logs (7 days)
└── misc/                   # SSH host keys, .env files, fail2ban, etc.
```

## Database notes

When passwordless sudo is available, the script automatically escalates to root before running database dumps. This handles the common case where databases (especially MySQL/MariaDB) use unix socket authentication that only permits the root OS user to connect.

If your databases require additional configuration:

- **MySQL/MariaDB**: Works automatically when running as root (via sudo or direct root SSH). If password authentication is required instead, create a `~/.my.cnf` on the server:
  ```ini
  [mysqldump]
  user=root
  password=yourpassword
  ```
- **PostgreSQL**: The script runs `pg_dumpall` as the `postgres` user via sudo.
- **MongoDB**: If auth is enabled, configure credentials in `/etc/mongod.conf` or pass them via environment variables.

## Security considerations

The resulting archive will contain sensitive material including database dumps, SSL private keys, `.env` files, SSH host keys, and other credentials. After downloading:

- **Encrypt the archive** before storing it anywhere:
  ```bash
  gpg -c linode-backup-myserver-20260212-143000.tar.gz
  ```
- **Do not commit the archive** to any repository
- **Review the contents** and remove anything you don't need to retain
- **Store securely** — treat it like a full server image

## Requirements

**Local machine**: Any Unix-like system with `ssh` and `scp` (macOS, Linux, WSL).

**Remote server**: The script adapts to what's installed. It uses `rsync` when available for smarter file copying but falls back to `cp` otherwise. Database dumps only run if the respective CLI tools are present.

**SSH access**: Running as `root` or as a user with passwordless sudo captures the most complete backup. The script automatically detects and uses passwordless sudo when available. If the SSH user has neither root access nor sudo, some directories and database dumps may be skipped.

## Limitations

- **Disk space**: The remote server needs enough free space in `/tmp` to stage the archive. For servers with very large datasets, consider excluding specific directories by modifying the script.
- **Block Storage volumes**: The script backs up mounted filesystems. If you have unmounted Block Storage volumes, attach and mount them before running the backup.
- **Database size**: Very large databases may take significant time to dump and transfer. For multi-gigabyte databases, consider running targeted dumps separately.
- **Docker volume export**: Uses an Alpine container to tar each volume. Requires the ability to run `docker run`.

## License

MIT
