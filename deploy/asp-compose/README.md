# ASP Docker Compose Deployment

Chinese version: [README.zh.md](README.zh.md)

This package deploys ASP on a single host with Docker Compose.

## First deployment

1. Run `./scripts/init.sh`. If `.env` does not exist, it is created from `.env.example` with random service secrets.
2. Add custom Module, Playbook, SIEM YAML, or Python requirements under `custom/` when needed.
3. Initialize and start ASP. When `custom/requirements.txt` is not empty, any arguments after `init.sh` are passed to `uv pip install`:

   ```bash
   ./scripts/init.sh --index-url https://pypi.org/simple
   ```

   Pass standard proxy variables when required:

   ```bash
   HTTP_PROXY=http://proxy.example:8080 HTTPS_PROXY=http://proxy.example:8080 \
   ./scripts/init.sh --index-url https://pypi.org/simple
   ```

4. If there are no custom Python dependencies, run:

   ```bash
   ./scripts/init.sh
   ```

5. Create an administrator:

   ```bash
   docker compose exec asp-web python manage.py createsuperuser
   ```

Review `.env` after initialization. You can edit it later to use custom passwords, host names, or ports. Do not keep `change-me-*` placeholder secrets in `.env`; `init.sh` refuses to start when placeholders are present.

## HTTPS certificates

`asp-frontend` listens on HTTPS only. The host bind address and port are controlled by `ASP_BIND` and `ASP_HTTPS_PORT` in `.env`; both default to server-friendly values:

```text
ASP_BIND=0.0.0.0
ASP_HTTPS_PORT=443
```

If `certs/asp.crt` and `certs/asp.key` do not exist, the frontend container generates a self-signed certificate on first start. The generated certificate uses `ASP_PUBLIC_HOSTNAME` plus `localhost` and `127.0.0.1` as SANs. Add extra SAN entries with `ASP_CERT_EXTRA_SAN`, for example:

```text
ASP_CERT_EXTRA_SAN=DNS:asp.example.com,IP:10.0.0.10
```

To use a custom certificate, place both files before starting or restart the frontend after replacing them:

```text
certs/asp.crt
certs/asp.key
```

```bash
docker compose restart asp-frontend
```

## Web API and upload limits

Adjust the Web API process and upload size in `.env`:

```text
ASP_WEB_WORKERS=3
ASP_WEB_TIMEOUT=210
ASP_MAX_UPLOAD_SIZE=20m
```

## Management UIs

Redis Stack and RustFS provide their own management UIs. They are exposed directly with their official HTTP ports to avoid reverse proxy compatibility issues:

- Redis Stack UI: `http://<server>:8001`
- RustFS Console: `http://<server>:9001`

RustFS S3 API stays internal by default and is not mapped to the host.

The host bind address and ports are controlled by `.env`:

```text
ASP_MANAGEMENT_BIND=0.0.0.0
ASP_REDIS_UI_PORT=8001
ASP_RUSTFS_CONSOLE_PORT=9001
```

The default bind address is `0.0.0.0` for server deployments. Use firewall or VPN controls when these management UIs should not be reachable from untrusted networks.

## Compose customization

When the file does not exist, `init.sh` creates a `compose.override.yaml` with explanatory comments and an empty `services: {}` mapping. Docker Compose automatically merges it with the official `compose.yaml`.

- Keep supported passwords, ports, and image settings in `.env`.
- Edit `compose.override.yaml` for service-level additions such as volumes, environment variables, or command overrides.
- The upgrader replaces the official `compose.yaml` but never overwrites `.env` or `compose.override.yaml`.

Do not edit the official `compose.yaml` directly; the next managed upgrade backs up and replaces those changes.

## Custom definitions

- `custom/modules/*.py` contains custom Module scripts.
- `custom/playbooks/*.py` contains custom Playbook scripts.
- `custom/data/modules/<module_slug>/raw_alert_*.json` contains Module development samples.
- `custom/data/siem/*.yaml` contains custom SIEM schema files.
- `custom/data/playbooks/<playbook_slug>/*.md` contains custom Playbook prompts.
- `custom/requirements.txt` contains extra Python packages.

After changing only script or YAML definitions, use **System Settings > Runtime > Refresh / Validate** in ASP. After changing Python package dependencies or imported helper modules, rerun `asp-custom-deps` and restart related containers.

## Logs

Nginx and backend process logs are mounted to `./logs`:

```text
logs/nginx/access.log
logs/nginx/error.log
logs/django.log
logs/asgi.log
logs/agentic-module-worker.log
logs/agentic-case-analysis-worker.log
logs/agentic-playbook-worker.log
logs/elk-action-worker.log
logs/dashboard-cache-worker.log
```

Container stdout and stderr are still available through `docker compose logs`.

## Operations

Check service status and run deployment diagnostics:

```bash
docker compose ps
./scripts/doctor.sh
```

`doctor.sh` waits for every official long-running service to become running/healthy, then checks PostgreSQL, Redis, Django, custom definitions, and the RustFS/S3 bucket.

Restart all services:

```bash
docker compose restart
```

Restart only the Web/API entrypoints:

```bash
docker compose restart asp-frontend asp-web asp-asgi
```

The reverse proxy must forward `/ws/` to the ASGI service.

Restart only background workers:

```bash
docker compose restart asp-worker-module asp-worker-case-analysis asp-worker-playbook asp-worker-elk-action asp-worker-dashboard-cache
```

After changing `.env`, `compose.yaml`, or port mappings, run:

```bash
docker compose up -d
```

Stop containers while keeping Docker volumes:

```bash
docker compose stop
```

Do not run `docker compose down -v` in production unless you explicitly want to delete PostgreSQL, Redis, and RustFS Docker volumes.

## Backup & Restore

Run backups and restores from a deployment directory named `asp-compose`, so Docker Compose volume names stay unchanged.

Full stopped backup:

```bash
BACKUP_DIR="$PWD/backups/asp-full-$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"
docker compose stop
tar -czf "$BACKUP_DIR/files.tar.gz" --exclude='./backups' .env .env.example compose*.yaml scripts custom certs logs
docker run --rm \
  -v asp-compose_postgres-data:/volumes/postgres-data:ro \
  -v asp-compose_redis-data:/volumes/redis-data:ro \
  -v asp-compose_rustfs-data:/volumes/rustfs-data:ro \
  -v asp-compose_custom-python-packages:/volumes/custom-python-packages:ro \
  -v asp-compose_static-files:/volumes/static-files:ro \
  -v "$BACKUP_DIR:/backup" \
  alpine sh -lc 'cd /volumes && tar -czf /backup/volumes.tar.gz postgres-data redis-data rustfs-data custom-python-packages static-files'
docker compose up -d
./scripts/doctor.sh
```

Full restore:

```bash
BACKUP_DIR=/path/to/asp-full-backup
tar -xzf "$BACKUP_DIR/files.tar.gz" -C .
docker compose down --remove-orphans
docker run --rm \
  -v asp-compose_postgres-data:/volumes/postgres-data \
  -v asp-compose_redis-data:/volumes/redis-data \
  -v asp-compose_rustfs-data:/volumes/rustfs-data \
  -v asp-compose_custom-python-packages:/volumes/custom-python-packages \
  -v asp-compose_static-files:/volumes/static-files \
  -v "$BACKUP_DIR:/backup" \
  alpine sh -lc '
    for dir in postgres-data redis-data rustfs-data custom-python-packages static-files; do
      rm -rf "/volumes/$dir"/* "/volumes/$dir"/.[!.]* "/volumes/$dir"/..?*
    done
    tar -xzf /backup/volumes.tar.gz -C /volumes
  '
docker compose up -d
./scripts/doctor.sh
```

Do not change the `asp-compose` directory name before restoring.

## Upgrade

Before upgrading, complete a full stopped backup.

When the local upgrade script supports managed upgrades, run this from the deployment directory:

```bash
./scripts/upgrade.sh --version <version>
```

The script downloads the target Release Compose package and SHA-256 file, verifies and backs up official files, updates image tags in `.env`, then pulls images, runs migrations, starts services, and checks every long-running service.

Use a non-executing text check to see whether an older deployment script supports `--version`:

```bash
grep -q -- '--version' ./scripts/upgrade.sh
```

If the command finds no match, download the one-time upgrader from the target Release:

```bash
version="<version>"
base_url="https://github.com/FunnyWolf/agentic-soc-platform/releases/download/v${version}"
curl -fL -O "${base_url}/asp-upgrade-${version}.sh"
curl -fL -O "${base_url}/asp-upgrade-${version}.sh.sha256"
sha256sum -c "asp-upgrade-${version}.sh.sha256" &&
  chmod +x "asp-upgrade-${version}.sh" &&
  ./asp-upgrade-${version}.sh --version "${version}"
```

The upgrader manages `compose.yaml`, `scripts/`, `.env.example`, `README.md`, and `README.zh.md`. It preserves `.env`, `compose.override.yaml`, `custom/`, `certs/`, `logs/`, and Docker named volumes.

Failures before migration restore the old files automatically. Automatic downgrade is disabled after database migration starts; the script prints the `backups/upgrade-<version>-<timestamp>-<pid>/` path for troubleshooting.
