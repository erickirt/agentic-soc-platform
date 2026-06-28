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

## Custom definitions

- `custom/modules/*.py` contains custom Module scripts.
- `custom/playbooks/*.py` contains custom Playbook scripts.
- `custom/data/modules/<module_slug>/raw_alert_*.json` contains Module development samples.
- `custom/data/siem/*.yaml` contains custom SIEM schema files.
- `custom/data/playbooks/<playbook_slug>/*.md` contains custom Playbook prompts.
- `custom/requirements.txt` contains extra Python packages.

After changing only script or YAML definitions, use **System Settings > Runtime > Refresh / Validate** in ASP. After changing Python package dependencies or imported helper modules, rerun `asp-custom-deps` and restart related containers.

## Logs

Backend process logs are mounted to `./logs`:

```text
logs/django.log
logs/asgi.log
logs/agentic-module-worker.log
logs/agentic-case-analysis-worker.log
logs/agentic-playbook-worker.log
logs/elk-action-worker.log
```

Container stdout and stderr are still available through `docker compose logs`.

## Operations

Check service status and run deployment diagnostics:

```bash
docker compose ps
./scripts/doctor.sh
```

Restart all services:

```bash
docker compose restart
```

Restart only the Web/API entrypoints:

```bash
docker compose restart asp-frontend asp-web asp-asgi
```

Restart only background workers:

```bash
docker compose restart asp-worker-module asp-worker-case-analysis asp-worker-playbook asp-worker-elk-action
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

## Upgrade

Before upgrading, back up at least `.env`, `custom/`, `certs/`, and PostgreSQL data:

```bash
mkdir -p backups
set -a
. ./.env
set +a

tar -czf "backups/asp-config-$(date +%Y%m%d%H%M%S).tar.gz" .env custom certs
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > "backups/postgres-$(date +%Y%m%d%H%M%S).sql"
```

Replace `compose.yaml`, `scripts/`, and `.env.example` from the new release package, then update the image tags in your existing `.env`:

```text
ASP_BACKEND_IMAGE=ghcr.io/funnywolf/agentic-soc-platform/asp-backend:<version>
ASP_FRONTEND_IMAGE=ghcr.io/funnywolf/agentic-soc-platform/asp-frontend:<version>
```

Run the upgrade:

```bash
./scripts/upgrade.sh
```

`upgrade.sh` pulls images, runs database migrations, starts services, and executes `./scripts/doctor.sh`.
