# ASP custom 运行目录设计

## 背景

ASP 需要把本地开发、测试和单机 Compose 生产部署的定制机制统一起来。当前已经引入 `custom/` 作为 Module、Playbook、SIEM YAML 和额外 Python 依赖的运行入口，但仍存在两个问题：

- `backend/examples` 会让示例与真实运行目录分离，开发者需要复制文件才能测试。
- 内置 Module、SIEM YAML 和自定义 Playbook 示例的生产边界需要更清晰，避免测试内容进入生产默认运行路径。

## 决策

`backend/custom` 作为源码开发环境的 canonical custom 目录；Compose 发布包中的 `custom/` 使用相同目录结构，但默认只提供空模板，不包含测试样例。Docker 镜像不包含源码 `backend/custom`，生产运行时只读取挂载的发布包 `custom/`。

## 目标

- 删除 `backend/examples` 概念。
- 让本地开发直接使用 `backend/custom` 验证 Module、SIEM YAML、custom Playbook、custom Prompt 和 `requirements.txt`。
- 让生产发布包保留空 `custom/` 模板，避免默认加载测试 Module 或测试 SIEM schema。
- 保留官方 Playbook 的产品能力，同时提供一个 custom LLM Playbook 示例用于验证扩展机制。
- 更新文档和 `asp-marketplace` 中对应 Skills，使路径说明一致。

## 非目标

- 不把 custom 测试内容打进 Docker 镜像。
- 不让发布包默认加载测试 Module、测试 SIEM YAML 或测试 custom Playbook。
- 不改变官方 Playbook 的运行模型，除 `cmdb_enrichment` 迁出为 custom 示例外。

## 目录结构

源码开发目录：

```text
backend/custom/
  modules/
    aws_iam_privilege_escalation_attach_user_policy.py
    edr_vssadmin_delete_shadows.py
    mail_user_report_phishing.py
  data/
    modules/
      aws_iam_privilege_escalation_attach_user_policy/raw_alert_*.json
      edr_vssadmin_delete_shadows/raw_alert_*.json
      mail_user_report_phishing/raw_alert_*.json
    siem/
      siem-aws-cloudtrail.yaml
      siem-host-events.yaml
      siem-network-traffic.yaml
    playbooks/
      case_summary/System_en.md
      case_summary/System_zh.md
  playbooks/
    cmdb_enrichment.py
    case_summary.py
  requirements.txt
```

Compose 发布包目录保持同构，但默认为空模板：

```text
custom/
  modules/
  data/
    modules/
    siem/
    playbooks/
  playbooks/
  requirements.txt
```

## 运行加载规则

- Module 只加载 `custom/modules/*.py`。
- SIEM YAML 只加载 `custom/data/siem/*.yaml`。
- 官方 Playbook 保留：
  - `backend/playbooks/investigation.py`
  - `backend/playbooks/knowledge_extraction.py`
  - `backend/playbooks/threat_intelligence_enrichment.py`
- 自定义 Playbook 加载 `custom/playbooks/*.py`，可追加或覆盖同名官方 Playbook。
- `backend/data` 只保留产品运行时 Prompt，不再放 Module 或 SIEM 示例数据。

## 自定义 Playbook Prompt

新增一个 custom LLM Playbook 示例：

```text
backend/custom/playbooks/case_summary.py
backend/custom/data/playbooks/case_summary/System_en.md
backend/custom/data/playbooks/case_summary/System_zh.md
```

提供通用 Prompt 读取能力，供 custom Playbook 调用，例如：

```python
self.read_prompt("System")
```

读取路径为：

```text
custom/data/playbooks/<playbook_slug>/System_<prompt_language>.md
```

如果 Prompt 文件不存在，Playbook 执行失败并把明确错误写入 `remark`，不使用空 Prompt 或静默 fallback。

`case_summary.py` 读取 Case 及其关联 Alert、Artifact、Enrichment 的摘要上下文，调用当前 LLM Provider，生成并写回 `case.summary`，返回执行摘要。它用于验证 custom Playbook 加载、custom Prompt 加载、LLM 调用和 Case 写回。

## 错误处理与刷新校验

`Refresh / Validate` 需要覆盖：

- Module：扫描 `custom/modules/*.py`，返回 `name`、`stream_name`、`path` 和加载错误。
- SIEM YAML：扫描 `custom/data/siem/*.yaml`，返回 `name`、`backend`、`path` 和加载错误。
- Playbook：扫描官方目录和 `custom/playbooks/*.py`，返回 `source`、`name`、`tags`、`path` 和加载错误。
- Prompt：至少校验 `case_summary` 的 `System_en.md` 和 `System_zh.md` 是否存在。

加载错误只影响对应文件，不阻塞 ASP 启动。如果 `custom/requirements.txt` 或 helper module 变更，仍要求重新安装依赖并重启相关容器。

## 验证标准

本地源码环境：

- `refresh_custom_definitions()` 应返回 `modules=3`、`siem=3`、`playbooks=5`，其中 Playbook 为 3 个官方 + 2 个 custom。
- `case_summary` 可在已有 Case 上运行，并写回 `summary`。

生产 Compose 空模板：

- `refresh_custom_definitions()` 应返回 `modules=0`、`siem=0`、`playbooks=3`。
- 空 `custom/requirements.txt` 不触发依赖安装。

文档与 marketplace：

- `asf-doc` 中 Module、SIEM YAML、custom Playbook 的路径全部使用 `custom/...`。
- `asp-marketplace` 中 Module Creator、SIEM Index YAML、Playbook 相关 Skill 全部使用新目录。
- 不再出现 `backend/examples`、`backend/modules`、`backend/data/siem` 作为运行或生成路径。

