# ASP Docker Compose 部署

英文版本：[README.md](README.md)

该发布包用于在单台 Linux 主机上通过 Docker Compose 部署 ASP。

> 所有命令都在名为 `asp-compose` 的部署目录中执行。不要修改目录名，否则 Docker Compose project name 和 named volumes 名称会发生变化。

## 首次部署

初始化并启动：

```bash
./scripts/init.sh
```

`init.sh` 会创建运行目录、`compose.override.yaml` 和 `.env`，生成 Django、PostgreSQL、Redis、RustFS 随机凭据，拉取镜像、执行数据库迁移并启动服务。

检查部署：

```bash
./scripts/doctor.sh
```

创建管理员：

```bash
docker compose exec asp-web python manage.py createsuperuser
```

## 环境变量

部署配置保存在 `.env`。初始化生成的随机服务凭据无需手工修改；初始化后不要只修改 PostgreSQL、Redis 或 RustFS 密码，否则应用与服务端凭据会不一致。

修改其他 `.env` 配置后执行：

```bash
docker compose up -d
./scripts/doctor.sh
```

## HTTPS 证书

默认 HTTPS 入口为：

```text
https://<server>:443
```

如果 `certs/asp.crt` 和 `certs/asp.key` 不存在，前端首次启动时会生成自签名证书。正式环境请把证书放到：

```text
certs/asp.crt
certs/asp.key
```

替换证书后重启前端：

```bash
docker compose restart asp-frontend
```

## 管理界面

- Redis Stack UI：`http://<server>:8001`
- RustFS Console：`http://<server>:9001`

端口和绑定地址由 `.env` 中的 `ASP_MANAGEMENT_BIND`、`ASP_REDIS_UI_PORT`、`ASP_RUSTFS_CONSOLE_PORT` 控制。生产环境应通过防火墙或 VPN 限制访问。

## 定制内容

`init.sh` 会创建：

```text
custom/modules/
custom/playbooks/
custom/data/modules/
custom/data/siem/
custom/data/playbooks/
custom/requirements.txt
```

只修改 Module、Playbook 或 SIEM YAML 后，在 ASP 的 Custom Console 中执行 `Refresh / Validate`。

新增 Python 依赖时，写入 `custom/requirements.txt` 并执行：

```bash
docker compose run --rm asp-custom-deps
docker compose restart asp-web asp-worker-module asp-worker-playbook
./scripts/doctor.sh
```

## Compose 定制

已有配置优先写入 `.env`。需要增加 volume、环境变量、command 或其他服务级覆盖时，编辑 `compose.override.yaml`。

不要直接修改官方 `compose.yaml`；升级时最新发布包会覆盖该文件。发布包不包含 `.env`、`compose.override.yaml`、`custom/`、`certs/` 和 `logs/`。

## 运维

查看状态并运行完整诊断：

```bash
docker compose ps
./scripts/doctor.sh
```

查看服务日志：

```bash
docker compose logs --tail=100 <service>
docker compose logs -f <service>
```

Nginx 和后端进程日志也会写入 `logs/`。

重启、停止和启动：

```bash
docker compose restart
docker compose stop
docker compose up -d
```

不要执行 `docker compose down -v`，除非明确要删除全部持久化数据。

## 备份 & 恢复

创建停机全量备份：

```bash
./scripts/backup.sh
```

指定其他备份根目录：

```bash
./scripts/backup.sh /mnt/asp-backups
```

恢复全量备份：

```bash
./scripts/restore.sh /path/to/asp-full-backup
```

恢复会替换当前部署文件和 Docker named volumes。脚本会在停止服务前校验备份 manifest、SHA-256、归档文件和 Compose 配置。

## 升级

先在当前部署目录创建全量备份：

```bash
./scripts/backup.sh
```

返回父目录，下载并覆盖最新发布包，然后执行新包中的升级脚本：

```bash
cd ..
curl -fL -o asp-compose.tar.gz https://github.com/FunnyWolf/agentic-soc-platform/releases/latest/download/asp-compose.tar.gz &&
tar -xzf asp-compose.tar.gz &&
rm asp-compose.tar.gz &&
cd asp-compose &&
./scripts/upgrade.sh
```

升级脚本会更新镜像、停止旧版本应用服务、执行目标版本升级操作和数据库迁移、启动服务并运行 `doctor.sh`。升级不会自动回滚；需要完整恢复时使用升级前的全量备份。
