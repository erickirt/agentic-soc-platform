# asf-doc 中文文档重构设计

## 背景

`asf-doc/docs/zh` 仍保留较多旧版本 ASP 框架、插件和模块叙事。当前项目已经转向以 ASP 工作台为核心的产品形态，文档需要按当前 backend、frontend 和 ClaudeCode 插件能力重新组织。

旧版本说明、迁移说明和兼容说明不再保留。无法从旧内容确认映射关系时，以当前代码为准；业务含义不确定时向用户确认。

## 目标

- 重构中文文档信息架构，使其贴合当前 ASP 产品工作台。
- 删除不属于新结构的旧中文文档文件。
- 为每个新章节提供简洁、当前态、可用的首版内容。
- 保留 Release / 更新日志栏目，但它只作为版本记录，不承担当前功能说明。
- ClaudeCode 插件保留在集成章节；MCP 只作为 ClaudeCode 连接机制说明，不作为独立主线。

## 非目标

- 不同步英文文档。
- 不编写旧版本迁移或兼容说明。
- 不修改 backend/frontend 业务代码。
- 不把 asp-marketplace 作为本次文档主线；它未来会单独发布为 GitHub 项目，本次影响仅限 ClaudeCode 插件说明。
- 不在第一阶段补大量截图、长篇示例或完整 API 手册。

## 信息架构

中文文档主线调整为产品工作台优先：

1. 概览
   - 什么是 Agentic SOC Platform
   - 产品架构与核心工作流
   - 术语表：Case、Alert、Artifact、Enrichment、Knowledge、Playbook、Audit、Inbox
2. 快速开始
   - 部署
   - 首次登录
   - 基础配置
   - 连接 LLM、SIEM、威胁情报、LDAP
3. 工作台功能
   - Dashboard
   - Case
   - Alert
   - Artifact
   - Enrichment
   - Knowledge
   - Playbook
   - Inbox / 通知
   - Audit Log / 审计
4. 系统设置
   - 用户与权限
   - API Key
   - LLM Provider
   - SIEM：Splunk / ELK
   - 威胁情报：AlienVault OTX
   - LDAP
   - Agentic Runtime
5. 集成
   - Webhook：Splunk / Kibana 告警接入
   - ClaudeCode 插件：安装、能力边界、可用 Skills / Agents
6. 开发扩展
   - 数据模型与 API 约定
   - Playbook 扩展
   - 当前 `backend/modules` 与 `backend/playbooks` 中仍存在的真实示例
7. 更新日志
   - 保留 Release 页面和入口
   - 不用历史版本说明替代当前功能说明

## 内容规则

- 简洁优先，每页只写当前用户需要知道的内容。
- 当前功能说明以 `backend/apps`、`frontend/src` 和 ClaudeCode 插件现状为准。
- 首页 hero/features 同步当前产品定位，避免旧版本宣传口径。
- 旧的 `feature/`、`background/`、`modules/`、`playbooks/`、`integrations/` 中不符合新结构的页面删除或迁移。
- 真实 backend modules/playbooks 示例可迁移到开发扩展章节，但不沿用旧叙事。

## 实施方案

- 主工作区：`asf-doc/docs/zh`。
- 配置入口：`asf-doc/docs/.vitepress/config/zh.ts`。
- 新路径采用小写英文目录，优先使用稳定路径，例如 `overview/`、`quick-start/`、`workspace/`、`settings/`、`integrations/`、`development/`、`release/`。
- 先调整导航和目录，再写首版内容，最后删除未进入新结构的旧文件。
- 如果现有 Release 路径可用，保留现有路径，避免无意义重命名。

## 校验

- 使用 asf-doc 已有 package scripts 验证 VitePress 文档构建或链接。
- 不运行 frontend 产品 build。
- 若发现文档链接、导航路径或业务含义不确定，停止并向用户确认。

## 分阶段执行

第一阶段：

- 完成 zh 信息架构重构。
- 删除旧中文文档文件。
- 写入每个新章节的简洁首版内容。
- 保留 Release 栏目。

第二阶段：

- 按功能页补操作步骤、截图、字段解释和典型场景。
- 根据 ClaudeCode 插件独立仓库发布情况，同步安装链接和 marketplace 说明。
- 深化 Playbook/module 开发示例。
