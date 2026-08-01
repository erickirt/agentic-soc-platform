# ASP Docker Compose Deployment

Chinese version: [README.zh.md](README.zh.md)

This package deploys ASP on a single Linux host with Docker Compose.

> Run every command from a deployment directory named `asp-compose`. Do not rename it, because the Docker Compose project name and named volume names would change.

## First deployment

Initialize and start ASP:

```bash
./scripts/init.sh
```

`init.sh` creates runtime directories, `compose.override.yaml`, and `.env`; generates random Django, PostgreSQL, Redis, and RustFS credentials; pulls images; runs database migrations; and starts services.

Check the deployment:

```bash
./scripts/doctor.sh
```

Create an administrator:

```bash
docker compose exec asp-web python manage.py createsuperuser
```

## Environment variables

Deployment settings are stored in `.env`. The generated random service credentials do not need to be changed manually. After initialization, do not change only the PostgreSQL, Redis, or RustFS password in `.env`, because application and server credentials would no longer match.

After changing other `.env` settings, run:

```bash
docker compose up -d
./scripts/doctor.sh
```

## HTTPS certificates

The default HTTPS entrypoint is:

```text
https://<server>:443
```

If `certs/asp.crt` and `certs/asp.key` do not exist, the frontend generates a self-signed certificate on first start. For production, place the certificate files at:

```text
certs/asp.crt
certs/asp.key
```

Restart the frontend after replacing them:

```bash
docker compose restart asp-frontend
```

## Management UIs

- Redis Stack UI: `http://<server>:8001`
- RustFS Console: `http://<server>:9001`

The bind address and ports are controlled by `ASP_MANAGEMENT_BIND`, `ASP_REDIS_UI_PORT`, and `ASP_RUSTFS_CONSOLE_PORT` in `.env`. Restrict production access with a firewall or VPN.

## Custom content

`init.sh` creates:

```text
custom/modules/
custom/playbooks/
custom/data/modules/
custom/data/siem/
custom/data/playbooks/
custom/requirements.txt
```

After changing only Module, Playbook, or SIEM YAML definitions, run `Refresh / Validate` in the ASP Custom Console.

For new Python dependencies, update `custom/requirements.txt` and run:

```bash
docker compose run --rm asp-custom-deps
docker compose restart asp-web asp-worker-module asp-worker-playbook
./scripts/doctor.sh
```

## Compose customization

Keep supported settings in `.env`. Edit `compose.override.yaml` for service-level additions such as volumes, environment variables, or command overrides.

Do not edit the official `compose.yaml` directly; the latest release package overlays it during upgrades. Release packages do not contain `.env`, `compose.override.yaml`, `custom/`, `certs/`, or `logs/`.

## Operations

Check status and run complete diagnostics:

```bash
docker compose ps
./scripts/doctor.sh
```

View service logs:

```bash
docker compose logs --tail=100 <service>
docker compose logs -f <service>
```

Nginx and backend process logs are also written under `logs/`.

Restart, stop, and start services:

```bash
docker compose restart
docker compose stop
docker compose up -d
```

Do not run `docker compose down -v` unless you explicitly intend to delete all persistent data.

## Backup & Restore

Create a stopped full backup:

```bash
./scripts/backup.sh
```

Use a different backup root:

```bash
./scripts/backup.sh /mnt/asp-backups
```

Restore a full backup:

```bash
./scripts/restore.sh /path/to/asp-full-backup
```

A restore replaces the current deployment files and Docker named volumes. Before stopping services, the script verifies the backup manifest, SHA-256 checksums, archives, and Compose configuration.

## Upgrade

First create a full backup from the current deployment directory:

```bash
./scripts/backup.sh
```

Return to the parent directory, download and overlay the latest release package, then run the upgrade script from the new package:

```bash
cd ..
curl -fL -o asp-compose.tar.gz https://github.com/FunnyWolf/agentic-soc-platform/releases/latest/download/asp-compose.tar.gz &&
tar -xzf asp-compose.tar.gz &&
rm asp-compose.tar.gz &&
cd asp-compose &&
./scripts/upgrade.sh
```

The upgrade script updates images, stops the current application services, runs target-release upgrade operations and database migrations, starts services, and runs `doctor.sh`. Upgrades do not roll back automatically; use the full backup when a complete restore is required.
