# ASP 单机 Docker Compose 分发设计

## 背景

ASP 当前由 Django 后端、Vite 前端、PostgreSQL、Redis、S3 兼容对象存储和多个后台 worker 组成。项目已有依赖服务的 Compose 示例，但还没有应用级 Dockerfile、完整 Compose 分发包和一键部署流程。

目标用户优先定位为单机或小团队私有化部署：一台服务器上尽量少步骤启动，并能保留必要的定制开发能力。

## 决策

ASP 首选分发形态采用版本化 Docker Compose 应用包。每个 release 发布镜像和一个 `asp-compose-<version>.tar.gz`，用户通过 `.env`、`custom/` 和持久化 volume 管理本地配置、数据和定制代码。

不采用 All-in-one 单容器作为主路径，因为 ASP 包含前端、HTTP API、ASGI/MCP、多个 worker 和状态服务，单容器会降低排障、升级和定制开发的可维护性。原生安装包可以作为未来补充，但不是单机部署首选。

## 目标

- 用户在单机环境中通过 Docker Compose 完成部署。
- 产品镜像和用户定制内容分离，升级时不要求用户修改产品源码。
- Module、Playbook、SIEM YAML 和额外 Python 依赖是分发包的一等能力。
- 支持管理员手动刷新/校验 Module、Playbook 和 SIEM YAML 定义。
- 初始化、升级和健康检查有明确命令，失败时显式报错。
- 默认路径适合联网安装；代理和自定义安装源通过原生 `uv pip install` 参数支持。

## 非目标

- 不在本设计中覆盖 Kubernetes/Helm 部署。
- 不把用户定制代码打进官方镜像作为默认流程。
- 不支持文件监听式自动热加载；刷新/校验由管理员显式触发。
- 不承诺额外依赖包、已导入 helper module 或 Python 包升级的无重启热替换；这类变更仍要求重启相关容器。
- 不为直接修改产品源码提供升级兼容承诺。

## 容器架构

单机 Compose 包含以下服务：

| 服务 | 作用 |
| --- | --- |
| `asp-frontend` | Nginx 托管 Vite build 产物，并反向代理 `/api/` 和 `/api/mcp`。 |
| `asp-web` | Django HTTP API、Admin、普通业务接口。 |
| `asp-asgi` | Django ASGI/MCP，服务 `/api/mcp`。 |
| `asp-worker-module` | 执行 `run_agentic_module_worker`。 |
| `asp-worker-case-analysis` | 执行 `run_agentic_case_analysis_worker`。 |
| `asp-worker-playbook` | 执行 `run_agentic_playbook_worker`。 |
| `asp-worker-elk-action` | 执行 `run_elk_action_worker`。 |
| `asp-migrate` | 一次性迁移/初始化服务，不常驻。 |
| `asp-custom-deps` | 一次性安装用户自定义 Python 依赖，不常驻。 |
| `postgres` | 默认内置 PostgreSQL。 |
| `redis-stack` | 默认内置 Redis/Redis Stack。 |
| `rustfs` | 默认内置 S3 兼容对象存储。 |

应用容器尽量无状态；PostgreSQL、Redis、RustFS 和 custom dependency volume 持久化。前端是单一入口，后端 HTTP、ASGI/MCP 和 worker 独立运行，便于重启和排障。

## 发布包结构

每个版本发布一个 Compose 包：

```text
asp-compose/
  compose.yaml
  .env.example
  README.md
  scripts/
    init.sh
    upgrade.sh
    doctor.sh
    install-custom-deps.sh
  custom/
    modules/
    playbooks/
    data/siem/
    requirements.txt
```

用户只编辑 `.env` 和 `custom/`。`compose.yaml` 随 release 维护，升级时可替换。

## 定制开发

定制开发通过宿主机 `custom/` 目录进入容器：

- `custom/modules/*.py`：用户 Module。
- `custom/playbooks/*.py`：用户 Playbook。
- `custom/data/siem/*.yaml`：用户 SIEM YAML。
- `custom/requirements.txt`：用户 Module/Playbook 需要的额外 Python 包。

backend、ASGI 和 worker 容器挂载 `custom/`。运行时默认只从 `custom/modules` 加载 Module，只从 `custom/data/siem` 加载 SIEM YAML；Playbook 从产品内置目录和 `custom/playbooks` 加载，custom 可追加或覆盖内置 Playbook。

ASP 提供管理员触发的刷新/校验能力，用于重新扫描 Module、Playbook 和 SIEM YAML，并返回已加载定义、来源路径和加载错误。该操作写入审计日志。纯脚本定义或 YAML 变更可通过刷新/校验确认，并在 worker 下一轮处理或下一次 Playbook 列表/执行时生效。

如果变更涉及 `custom/requirements.txt`、额外 Python 包升级或被普通 `import` 导入的 helper module，用户需要重新安装依赖并重启相关容器，例如：

```bash
docker compose restart asp-worker-module asp-worker-playbook asp-asgi
```

## 自定义 Python 依赖

额外 Python 包不写入产品镜像的 `.venv`，也不修改官方 site-packages。分发包提供一次性服务 `asp-custom-deps`：

```bash
docker compose run --rm asp-custom-deps [uv pip install 参数]
```

该服务内部执行：

```bash
uv pip install --target /opt/asp/custom-packages -r /app/custom/requirements.txt "$@"
```

`/opt/asp/custom-packages` 使用独立 named volume 持久化。backend、ASGI 和 worker 通过 `PYTHONPATH=/opt/asp/custom-packages:/app/custom` 加载这些依赖。

用户指定安装源时直接传 `uv pip install` 参数：

```bash
docker compose run --rm asp-custom-deps --index-url https://pypi.tuna.tsinghua.edu.cn/simple
```

代理使用标准环境变量传递：

```bash
HTTP_PROXY=http://proxy.example:8080 \
HTTPS_PROXY=http://proxy.example:8080 \
docker compose run --rm asp-custom-deps --index-url https://pypi.org/simple
```

这种方式不要求用户重打官方镜像；如果后续需要把客户定制固化为交付镜像，可以再提供 `Dockerfile.custom` 作为高级流程。

## 首次部署流程

1. 解压 `asp-compose-<version>.tar.gz`。
2. 复制 `.env.example` 为 `.env`，配置域名、端口、密码、`DJANGO_SECRET_KEY`、对象存储参数。
3. 执行 `docker compose pull`。
4. 如有额外 Python 包，执行 `docker compose run --rm asp-custom-deps [uv pip install 参数]`。
5. 执行 `docker compose run --rm asp-migrate`，完成数据库迁移、静态资源准备和对象存储 bucket 初始化。
6. 执行 `docker compose up -d`。
7. 创建管理员账号，并执行 `scripts/doctor.sh` 检查运行状态。

## 升级流程

升级遵循产品版本和用户定制分离：

1. 备份 PostgreSQL、RustFS 数据和 `.env`、`custom/`。
2. 替换 release 包或更新镜像 tag。
3. 执行 `docker compose pull`。
4. 如 `custom/requirements.txt` 有变化，重跑 `asp-custom-deps`。
5. 执行 `docker compose run --rm asp-migrate`。
6. 执行 `docker compose up -d`。
7. 执行 `scripts/doctor.sh`。

官方兼容边界是公开的 Module、Playbook、Base API、SIEM YAML 格式和配置变量。用户直接修改产品源码不作为升级兼容路径。

## 错误处理与健康检查

- `asp-migrate` 失败时返回非 0，不继续伪装成功。
- `asp-custom-deps` 安装失败时返回非 0，不修改业务容器启动逻辑。
- Module/Playbook 加载失败应在对应 worker 日志和刷新/校验结果中输出文件名、类名和异常。
- 每个 worker 独立容器输出日志，便于区分 Module、Case Analysis、Playbook 和 ELK Action 问题。
- Compose healthcheck 覆盖 PostgreSQL、Redis、RustFS、backend API 和 frontend。
- `scripts/doctor.sh` 检查容器健康、数据库连接、Redis Stream、S3 bucket、MCP `/api/mcp`、custom 目录可读、custom packages 可导入和 custom 脚本可扫描。

## 发布验证

每个 release 至少验证三条路径：

1. 全新部署：空 volume、默认配置、创建管理员账号后可登录。
2. 带定制部署：提供 custom Module/Playbook/SIEM YAML 和 `custom/requirements.txt`，依赖安装后刷新/校验通过，worker 能加载。
3. 升级部署：旧版本数据、`.env` 和 `custom/` 保留，迁移后核心功能可用。

