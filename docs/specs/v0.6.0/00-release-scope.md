# v0.6.0 release scope

Status: Confirmed

## 1. Release objective

v0.6.0 面向单组织私有化部署，目标是让一个小型 SOC 团队完成稳定的告警分诊、案件调查、响应执行和日常运维。该版本以核心功能闭环为优先，不以 SaaS、多租户或大规模集群为目标。

## 2. Supported deployment

- 唯一正式支持的部署拓扑是单主机 Docker Compose。
- 不承诺 Kubernetes、横向扩容、多节点高可用或自动故障切换。
- 每种后台 Worker 正式支持一个实例；重复实例必须按 Worker Health Spec 拒绝启动。
- 数据库降级不受支持。回滚依赖升级前备份恢复。

## 3. Upgrade contract

- 必须支持从 v0.5.2 直接升级到 v0.6.0。
- 升级必须保留所有业务数据、用户、LDAP 配置、集成配置、API Key、附件和自定义脚本。
- 所有数据库变更必须提供 Django migration。
- migration 必须适用于已有数据，不得要求清空数据库。
- 升级流程继续先运行 migration，再启动应用服务和 Worker。
- 不承诺从 v0.5.1 或更早版本直接升级，也不提供 v0.6.0 到 v0.5.2 的数据库 downgrade。

## 4. Capacity baseline

正式验收使用现有 `generate_perf_data --scale medium` 数据规模：

| Resource | Baseline |
| --- | ---: |
| Users | 20 |
| Cases | 10,000 |
| Alerts | 100,000 |
| Artifacts | 50,000 |
| Alert-artifact links | 300,000 |
| Enrichments | 30,000 |
| Playbook runs | 10,000 |
| Knowledge records | 2,000 |
| Audit logs | 100,000 |

`large` 和 `extreme` 数据档位可用于开发压测，但不属于 v0.6.0 响应时间承诺。

## 5. Official compatibility matrix

| Area | Officially supported |
| --- | --- |
| SIEM | Splunk, ELK |
| LLM | OpenAI-compatible Chat Completions endpoints |
| Threat intelligence | AlienVault OTX, OpenCTI |
| Authentication | Local account, LDAP |
| Object storage | 当前 Compose 分发所配置的 S3-compatible storage |
| Cache/stream | 当前 Compose 分发所配置的 Redis |

代码枚举或 UI 示例中出现其他厂商名称，不代表官方连接器或兼容承诺。

## 6. Roles

v0.6.0 保持三个固定角色：

| Role | Meaning |
| --- | --- |
| Admin | 系统管理和全部业务写操作 |
| User / Analyst | 分析师业务写操作 |
| Viewer | 只读访问 |

不实现自定义角色、权限编辑器或团队级数据隔离。每个新功能必须在自己的 Spec 中定义三种角色的具体权限。

## 7. Language

- 正式 UI 只支持英文。
- 项目用户文档保持中英文版本，先完成中文再同步英文。
- v0.6.0 不引入前端 i18n 框架。

## 8. API compatibility

- v0.6.0 允许破坏性修改现有前端 API 和 `/api/agent/v1/`。
- 不创建 Agent API v2 作为兼容层。
- 不要求旧 CLI 或旧插件拒绝连接，也不维护其兼容性。
- 新 API 仍应有明确的 DRF schema，避免无意的响应漂移。

## 9. Confirmed functional domains

1. Case 批量分诊。
2. 案件合并。
3. Playbook 执行可观测性和控制。
4. Custom Variables。
5. Worker Health。
6. Integration Health。
7. SLA 管理，待详细讨论。
8. AI 质量评估，待详细讨论。
9. 抑制规则，待详细讨论。
10. Operations 页面整合，待详细讨论。

SLA、AI 质量评估和抑制规则都是 v0.6.0 正式发布的阻断项，但必须限制为最小可用闭环。

## 10. Explicit exclusions

- 多租户、组织/Workspace 隔离。
- Kubernetes 和高可用部署。
- OIDC、SAML 或其他 SSO。
- 自定义角色。
- Jira、ServiceNow 等专用连接器。
- 可视化或表单式 Playbook 编排器。
- Playbook 中途人工审批。
- 通用 HTTP/Webhook Connector 或统一厂商动作抽象。
- 全站 UI 国际化。
- 旧 CLI/插件兼容层。
- 自动 Unmerge。

## 11. Cross-domain invariants

- merged source Case 默认不得进入 Dashboard、SLA、案件数量和正常列表统计。
- Case 单条编辑和批量编辑必须调用同一服务端状态机。
- Playbook、Module 和 Worker 错误不得向 API 暴露原始凭据、响应正文或 traceback。
- Admin 管理动作按各 Spec 写 AuditLog；高频健康遥测不写 AuditLog。
- 所有时间使用 timezone-aware UTC 存储，前端按浏览器时区显示。
- 所有列表型 API 必须分页；动态 Stage 数量不设上限，因此 Stage API 尤其不得全量返回。
- 业务写操作不得通过前端限制替代服务端权限和状态校验。
