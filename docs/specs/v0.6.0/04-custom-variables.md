# Custom Variables

Status: Confirmed

## 1. Purpose

提供一个由 Admin 通过 UI 管理、由自定义 Playbook 和 Agentic Module 在后端运行时读取的字符串变量仓库。它类似受控的数据库版环境变量，但不会修改真实 `os.environ`，也不影响 Django 全局配置。

典型用途：

- 外部系统 base URL。
- API token、username/password。
- tenant/project ID。
- 自定义 JSON 字符串。
- Module 或 Playbook 的运行参数。

## 2. Scope

### Consumers

- `BasePlaybook.get_variable(key)`
- `BaseModule.get_variable(key)`

### Not consumers

- Agent API。
- CLI 或插件。
- 前端运行时。
- Django template。
- 其他任意后端模块。
- 系统 Runtime Settings。

### Excluded

- 写入真实进程环境变量。
- 全局配置覆盖。
- per-Playbook/per-Module scope。
- 变量继承或 override。
- value 类型系统。
- `.env` 导入导出。
- REQUIRED_VARIABLES 声明。
- Secret 加密、版本历史或自动泄露防护。

## 3. Data model

建议模型 `CustomVariable`：

| Field | Type | Rules |
| --- | --- | --- |
| id | UUID | primary key |
| key | CharField(128) | unique, immutable |
| value | TextField | non-empty, max 65,536 UTF-8 bytes |
| is_secret | Boolean | controls API masking only |
| description | TextField | optional |
| enabled | Boolean | default true |
| created_at | DateTime | auto |
| updated_at | DateTime | auto |

### Key validation

Regex：

```text
[A-Z][A-Z0-9_]{0,127}
```

- 全局唯一。
- 大小写敏感，但合法输入只有大写。
- 创建后不可改名。
- 修改 key 的 PATCH/PUT 返回 validation error。

### Value validation

- 必须至少一个字符。
- 以 UTF-8 bytes 计算，最多 65,536 bytes。
- 可包含换行。
- 不支持 binary。
- 不做 trim；空格可能是有意值，但零长度禁止。
- 更新 Secret 时省略 value 表示保留旧值。
- 显式 `""` 始终拒绝。

## 4. Storage security

已确认：

- Secret 和非 Secret 均以 PostgreSQL 明文保存。
- 数据库管理员、数据库泄露和未加密备份可以读取 Secret。
- `is_secret` 只控制 API/UI 显示与审计，不提供 cryptographic protection。
- 用户文档必须明确该限制。

不得在 AuditLog、普通 API response、异常文本或日志中复制 value。

## 5. Runtime API

Base class helper：

```python
def get_variable(self, key):
    ...
```

返回：

- Enabled 且存在：原始 `str`。
- 不存在：`None`。
- Disabled：`None`。
- 已删除：`None`。

行为：

- 每次调用都查询 PostgreSQL。
- 不做 per-run、per-message 或 Worker 全局缓存。
- Admin 在 Playbook/Module 运行中修改、Disabled 或删除变量，下一次读取立即看到变化。
- 不抛 missing variable 异常。
- 不支持 default 参数作为平台约定；自定义代码自行使用 `or` 或显式 None 处理。
- 不返回 is_secret/description 等 metadata。
- 不记录 read audit 或 usage relation。

建议共享 service 位于 `apps.settings.custom_variables` 或等价窄模块，BasePlaybook/BaseModule 只做代理，避免重复 ORM 代码。

## 6. Permissions

| Action | Admin | User | Viewer | Playbook/Module Worker |
| --- | --- | --- | --- | --- |
| List metadata | Yes | No | No | No |
| Read non-secret value via Admin API | Yes | No | No | N/A |
| Reveal secret | Yes | No | No | N/A |
| Create/update/delete | Yes | No | No | No |
| get_variable runtime | No direct API | No direct API | No direct API | Yes |

Worker 读取不根据发起 Playbook 的用户角色过滤。User 发起的 Playbook 仍可读取所有 Custom Variables，因此 Admin 必须只安装可信自定义代码。

## 7. Admin API

建议资源：

`/api/settings/custom-variables/`

### List/retrieve default representation

非 Secret：

```json
{
  "id": "...",
  "key": "EDR_BASE_URL",
  "value": "https://edr.internal.example",
  "is_secret": false,
  "description": "Production EDR API",
  "enabled": true
}
```

Secret：

```json
{
  "id": "...",
  "key": "EDR_API_TOKEN",
  "value": "",
  "value_configured": true,
  "is_secret": true,
  "description": "Production EDR token",
  "enabled": true
}
```

### Reveal

`POST /api/settings/custom-variables/{id}/reveal/`

- 仅 active Admin session。
- 不要求重新输入本地或 LDAP 密码。
- 返回一次明文 value。
- 每次请求写 AuditLog。
- 不应支持 bulk reveal。
- response 应使用 no-store cache headers。

### Update

- key 不可改。
- Secret update 未包含 value：保留旧值。
- Secret→non-secret：API 需要显式确认字段，例如 `confirm_secret_exposure=true`。
- 没有确认返回 400。
- non-secret→secret 正常允许。
- 所有 changes 审计不包含 value。

### Delete

- 允许硬删除。
- UI 必须二次确认。
- API 不负责扫描 Python 代码引用。
- 删除后运行时返回 None。
- 删除 AuditLog 保存 key、description、is_secret、enabled，不保存 value。

## 8. Audit

写 AuditLog：

- create
- update
- enable/disable（作为 update）
- reveal
- delete

不写：

- get_variable runtime read。
- Admin 普通 list/retrieve。

Secret 和非 Secret value 均不得进入 changes。可使用：

```json
{
  "changes": {
    "value": {"from": "***", "to": "***"},
    "enabled": {"from": true, "to": false}
  },
  "metadata": {
    "key": "EDR_API_TOKEN",
    "value_changed": true
  }
}
```

不保留旧 value，不支持 rollback。

## 9. Frontend

位置：System Settings 中新增 `Custom Variables`。

### List

- Key。
- Description。
- Secret 标记。
- Enabled。
- Value configured。
- Updated time。
- Edit/Delete actions。
- Secret 默认不可见。

### Create/edit modal

- Key 创建时可编辑，编辑时只读。
- Value 使用 multiline input；Secret 使用 password input。
- is_secret switch。
- enabled switch。
- description。
- value byte limit 提示。
- 编辑 Secret 时 value 留空表示不修改，UI 必须明确说明。

### Reveal

- Secret 行显示 Reveal。
- active Admin session 直接调用。
- 明文只显示在临时 Modal。
- Modal 关闭后从前端 state 清除。
- 不复制到列表 state、URL、localStorage 或 console。

### Secret downgrade

从 Secret 改为普通变量时显示额外确认：

> This value will become visible in normal Admin API responses and UI.

## 10. Interaction with custom code

示例：

```python
class Playbook(BasePlaybook):
    def run(self):
        base_url = self.get_variable("EDR_BASE_URL")
        token = self.get_variable("EDR_API_TOKEN")
        if not base_url or not token:
            raise ValueError("EDR custom variables are not configured.")
```

自定义代码责任：

- 检查 None。
- 解析 JSON/boolean/number。
- 不把 Secret 写入 log、Stage summary、remark、Enrichment 或异常。
- 为 HTTP 调用设置 timeout、TLS、proxy、重试和幂等。

平台不静态分析 key，也不展示“变量被哪些脚本使用”。

## 11. Migration and backup

- 新表 migration，无旧数据迁移。
- v0.5.2 现有 LLM/SIEM/LDAP/TI Secret 不自动复制到 Custom Variables。
- 备份/恢复自然包含明文 value。
- Compose 文档需提醒保护数据库备份。

## 12. Acceptance criteria

1. 只有 Admin 能访问资源和 Reveal。
2. key regex、唯一和不可改名规则生效。
3. 空 value 和超过 65,536 bytes 被拒绝。
4. Secret 默认 response 不含明文。
5. Admin Reveal 返回明文并写不含 value 的审计。
6. Secret→普通无确认被拒绝。
7. Playbook 和 Module 每次读取当前数据库值。
8. Disabled/missing/deleted 返回 None。
9. Agent API、CLI 和普通用户没有读取端点。
10. CRUD AuditLog 永不包含 old/new value。
11. 删除无需引用检查且立即影响运行时读取。

## 13. Known tradeoffs

- PostgreSQL 和备份保存明文 Secret。
- active Admin session 无需重新认证即可 Reveal。
- User 发起的可信 Playbook 可以间接使用全部 Secret。
- 平台无法阻止恶意或错误自定义代码泄露 Secret。
- 每次 ORM 查询增加少量开销，这是为即时一致性接受的成本。
