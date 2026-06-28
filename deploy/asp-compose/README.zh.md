# ASP Docker Compose 部署

英文版本：[README.md](README.md)

这个发布包用于在单台主机上通过 Docker Compose 部署 ASP。

## 首次部署

1. 执行 `./scripts/init.sh`。如果 `.env` 不存在，脚本会从 `.env.example` 创建 `.env`，并生成随机服务密钥。
2. 如有需要，将自定义 Module、Playbook、SIEM YAML 或 Python 依赖放到 `custom/` 目录。
3. 初始化并启动 ASP。如果 `custom/requirements.txt` 不为空，`init.sh` 后面的参数会传给 `uv pip install`：

   ```bash
   ./scripts/init.sh --index-url https://pypi.org/simple
   ```

   需要代理时使用标准环境变量：

   ```bash
   HTTP_PROXY=http://proxy.example:8080 HTTPS_PROXY=http://proxy.example:8080 \
   ./scripts/init.sh --index-url https://pypi.org/simple
   ```

4. 如果没有额外 Python 依赖，直接执行：

   ```bash
   ./scripts/init.sh
   ```

5. 创建管理员：

   ```bash
   docker compose exec asp-web python manage.py createsuperuser
   ```

初始化后请检查 `.env`。你可以继续修改密码、主机名或端口。不要在 `.env` 中保留 `change-me-*` 占位密钥；`init.sh` 会拒绝使用占位密钥启动。

## HTTPS 证书

`asp-frontend` 只监听 HTTPS。宿主机绑定地址和端口由 `.env` 中的 `ASP_BIND` 和 `ASP_HTTPS_PORT` 控制，默认值适合服务器部署：

```text
ASP_BIND=0.0.0.0
ASP_HTTPS_PORT=443
```

如果 `certs/asp.crt` 和 `certs/asp.key` 不存在，前端容器首次启动时会生成自签名证书。生成的证书会使用 `ASP_PUBLIC_HOSTNAME`，并包含 `localhost` 和 `127.0.0.1` 作为 SAN。可以通过 `ASP_CERT_EXTRA_SAN` 添加额外域名或 IP：

```text
ASP_CERT_EXTRA_SAN=DNS:asp.example.com,IP:10.0.0.10
```

如需使用自定义证书，请在启动前放置这两个文件，或替换后重启前端：

```text
certs/asp.crt
certs/asp.key
```

```bash
docker compose restart asp-frontend
```

## 管理界面

Redis Stack 和 RustFS 自带管理界面。发布包直接暴露它们的官方 HTTP 管理端口，避免反向代理带来的静态资源或 WebSocket 兼容问题：

- Redis Stack UI：`http://<server>:8001`
- RustFS Console：`http://<server>:9001`

RustFS S3 API 默认保持容器内部访问，不映射到宿主机。

宿主机绑定地址和端口由 `.env` 控制：

```text
ASP_MANAGEMENT_BIND=0.0.0.0
ASP_REDIS_UI_PORT=8001
ASP_RUSTFS_CONSOLE_PORT=9001
```

默认绑定地址是 `0.0.0.0`，适合服务器部署。如果管理界面不应被不可信网络访问，请使用防火墙或 VPN 进行访问控制。

## 定制定义

- `custom/modules/*.py` 存放自定义 Module 脚本。
- `custom/playbooks/*.py` 存放自定义 Playbook 脚本。
- `custom/data/modules/<module_slug>/raw_alert_*.json` 存放 Module 开发样本。
- `custom/data/siem/*.yaml` 存放自定义 SIEM schema 文件。
- `custom/data/playbooks/<playbook_slug>/*.md` 存放自定义 Playbook prompt。
- `custom/requirements.txt` 存放额外 Python 依赖。

只修改脚本或 YAML 定义后，可以在 ASP 中使用 **System Settings > Runtime > Refresh / Validate**。修改 Python 包依赖或公共 helper module 后，需要重新执行 `asp-custom-deps` 并重启相关容器。

## 日志

后端进程日志会挂载到 `./logs`：

```text
logs/django.log
logs/asgi.log
logs/agentic-module-worker.log
logs/agentic-case-analysis-worker.log
logs/agentic-playbook-worker.log
logs/elk-action-worker.log
```

容器标准输出和标准错误仍可通过 `docker compose logs` 查看。

## 运维

查看服务状态并执行部署诊断：

```bash
docker compose ps
./scripts/doctor.sh
```

重启所有服务：

```bash
docker compose restart
```

只重启 Web/API 入口：

```bash
docker compose restart asp-frontend asp-web asp-asgi
```

只重启后台 Worker：

```bash
docker compose restart asp-worker-module asp-worker-case-analysis asp-worker-playbook asp-worker-elk-action
```

修改 `.env`、`compose.yaml` 或端口映射后，执行：

```bash
docker compose up -d
```

停止容器但保留 Docker 数据卷：

```bash
docker compose stop
```

不要在生产环境执行 `docker compose down -v`，除非明确要删除 PostgreSQL、Redis 和 RustFS 的 Docker 数据卷。

## 升级

升级前至少备份 `.env`、`custom/`、`certs/` 和 PostgreSQL 数据：

```bash
mkdir -p backups
set -a
. ./.env
set +a

tar -czf "backups/asp-config-$(date +%Y%m%d%H%M%S).tar.gz" .env custom certs
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" > "backups/postgres-$(date +%Y%m%d%H%M%S).sql"
```

从新发布包替换 `compose.yaml`、`scripts/` 和 `.env.example`，然后在现有 `.env` 中更新镜像标签：

```text
ASP_BACKEND_IMAGE=ghcr.io/funnywolf/agentic-soc-platform/asp-backend:<version>
ASP_FRONTEND_IMAGE=ghcr.io/funnywolf/agentic-soc-platform/asp-frontend:<version>
```

执行升级：

```bash
./scripts/upgrade.sh
```

`upgrade.sh` 会拉取镜像、执行数据库迁移、启动服务，并执行 `./scripts/doctor.sh`。
