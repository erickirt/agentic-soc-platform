# GitHub CI/CD 发布设计

## 背景

ASP 最终会在 GitHub 上创建仓库并发布。项目当前已经具备 backend/frontend Dockerfile、Docker Compose 分发包、`deploy/package-asp-compose.sh` 打包脚本、uv 管理的 Django 后端、pnpm/Vite 前端，以及 GitHub Container Registry 可直接承载镜像。

`asf-doc` 是独立 GitHub 仓库，并已配置 Cloudflare Pages，因此主仓库 CI/CD 不负责构建或发布文档站。

## 决策

主仓库使用 GitHub Actions、GitHub Container Registry、GitHub Releases、GitHub Advanced Security/CodeQL/Dependabot 等 GitHub 工具链。发布主路径为推送 Git tag，例如 `v0.2.0`。

## 目标

- PR 和主分支 push 自动运行质量检查。
- 推送 `v*` tag 自动构建并发布 backend/frontend 镜像。
- 自动生成 `asp-compose-<version>.tar.gz` 并上传到 GitHub Release。
- Release 失败时不生成半成品 Release。
- 第一阶段保持流程简单，预留 SBOM、镜像签名和漏洞门禁的扩展空间。

## 非目标

- 不在主仓库构建 `asf-doc` 或发布 Cloudflare Pages。
- 不实现自动在线升级器。
- 不在第一阶段把全部安全扫描结果作为 Release 阻断。
- 不引入 GitHub 之外的 CI/CD 平台。

## Workflow 分层

### `ci.yml`

触发：

- `pull_request`
- `push` 到主分支

职责：

- Backend：
  - 安装 uv。
  - `uv sync --frozen`。
  - `python manage.py check`。
  - 运行已有 Django tests。
- Frontend：
  - 启用 Corepack/pnpm。
  - `pnpm install --frozen-lockfile`。
  - `pnpm exec eslint .`。
  - `pnpm exec tsc -b`。
  - `pnpm build`。
- Compose package：
  - 校验 `deploy/asp-compose/compose.yaml` 可解析。
  - dry-run 生成 `asp-compose-<version>.tar.gz`。
  - 校验 tar.gz 中的 `custom/` 是空模板，不包含源码 `backend/custom` 测试样例。

PR 必须通过 `ci.yml` 才能合并。

### `docker.yml`

触发：

- `push` tag `v*`
- `workflow_dispatch` 用于维护者手动重跑

职责：

- 使用 Docker Buildx 构建：
  - `backend/Dockerfile`
  - `frontend/Dockerfile`
- 推送到 GHCR：
  - `ghcr.io/<owner>/<repo>/asp-backend:<version>`
  - `ghcr.io/<owner>/<repo>/asp-frontend:<version>`
  - 可选 `latest`，只指向最新稳定 tag。

PR 阶段可以只执行 Docker build，不 push。

### `release.yml`

触发：

- `push` tag `v*`

职责：

- 等待或依赖镜像构建成功。
- 运行打包脚本生成 `asp-compose-<version>.tar.gz`。
- 确认 `.env.example` 中镜像 tag 指向当前版本。
- 创建 GitHub Release。
- 上传 `asp-compose-<version>.tar.gz`。
- 使用 GitHub auto-generated release notes，后续可替换为 Release Drafter。

如果镜像构建、打包或校验失败，则不创建 Release。

### `security.yml` 与 GitHub 安全能力

第一阶段启用：

- CodeQL。
- Secret scanning 和 push protection。
- Dependabot：
  - GitHub Actions。
  - Docker。
  - npm/pnpm。

Python/uv 依赖更新先不强行自动化；后续可以增加定期 workflow 执行 `uv lock --upgrade` 并开 PR。

## Release 产物

Tag `v0.2.0` 对应：

```text
ghcr.io/<owner>/<repo>/asp-backend:0.2.0
ghcr.io/<owner>/<repo>/asp-frontend:0.2.0
asp-compose-0.2.0.tar.gz
```

Release asset 保留版本号。虽然 GitHub Release 页面本身有 tag，但用户下载到本地后常会保留多个版本，版本号能避免文件覆盖和混淆。

## 用户升级流程

用户升级时：

1. 下载新版本 `asp-compose-<version>.tar.gz`。
2. 备份 PostgreSQL、RustFS、`.env`、`custom/`、`certs/`、`logs/`。
3. 解压新包。
4. 复制旧 `.env`、`custom/`、`certs/`、`logs/` 到新目录。
5. 执行 `scripts/upgrade.sh`。

用户如果希望固定部署路径，可以把解压后的目录重命名为 `asp-compose`，但 Release asset 仍保持版本化命名。

## 权限与安全

Workflow 使用最小权限：

- CI：`contents: read`。
- Docker publish：`contents: read`、`packages: write`。
- Release：`contents: write`、必要时 `packages: read`。

镜像推送和 Release 创建默认使用 `GITHUB_TOKEN`。发布 tag 应只允许维护者创建；主分支开启 branch protection，并要求 `ci.yml` 通过。

后续增强项：

- Trivy 镜像扫描。
- SBOM 生成和上传。
- cosign keyless 签名。
- GitHub Environments 和 Release approval。

这些增强项不阻塞第一阶段上线。

## 验证标准

- PR 修改 backend/frontend/deploy 时，`ci.yml` 能准确失败或通过。
- 推送 `v*` tag 后，GHCR 出现两个版本镜像。
- GitHub Release 出现 `asp-compose-<version>.tar.gz`。
- tar.gz 中 `compose.yaml`、`.env.example`、`scripts/`、空模板 `custom/`、`logs/`、`certs/` 完整。
- tar.gz 中不包含源码开发的 `backend/custom` 测试样例。
- 使用 Release tar.gz 后能执行 `scripts/init.sh` 和 `scripts/upgrade.sh`。

