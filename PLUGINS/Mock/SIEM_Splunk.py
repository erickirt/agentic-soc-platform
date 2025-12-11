import json
import re
from typing import List, Dict, Any, Annotated

from langchain_core.messages import SystemMessage, HumanMessage

# Assuming LLMAPI is correctly imported and configured for your environment
# from PLUGINS.LLM.llmapi import LLMAPI
# Temporarily mock LLMAPI if not directly available for testing the structure
try:
    from PLUGINS.LLM.llmapi import LLMAPI
except ImportError:
    print("Warning: Could not import PLUGINS.LLM.llmapi. Using a mock LLMAPI for development.")


    class MockLLMResponse:
        def __init__(self, content):
            self.content = content


    class MockLLM:
        def invoke(self, messages):
            # For testing, return a dummy JSON for known patterns or an empty list
            last_human_message = messages[-1].content
            if "index=windows" in last_human_message and "EventCode=4624" in last_human_message:
                return MockLLMResponse(json.dumps([
                    {
                        "_time": "2025-12-01T10:00:01.000Z",
                        "index": "windows",
                        "sourcetype": "WinEventLog:Security",
                        "host": "DESKTOP-VICTIM1",
                        "source": "WinEventLog",
                        "EventCode": "4624",
                        "ComputerName": "DESKTOP-VICTIM1",
                        "SubjectUserName": "S-1-5-18",
                        "TargetUserName": "victim_user",
                        "ProcessName": "C:\\Windows\\System32\\lsass.exe",
                        "LogonType": "2",
                        "_raw": "EventCode=4624 ComputerName=DESKTOP-VICTIM1 SubjectUserName=S-1-5-18 TargetUserName=victim_user LogonType=2"
                    },
                    {
                        "_time": "2025-12-01T10:00:02.000Z",
                        "index": "windows",
                        "sourcetype": "WinEventLog:Security",
                        "host": "DESKTOP-VICTIM1",
                        "source": "WinEventLog",
                        "EventCode": "4688",
                        "ComputerName": "DESKTOP-VICTIM1",
                        "SubjectUserName": "victim_user",
                        "ProcessName": "C:\\Windows\\System32\\cmd.exe",
                        "ParentProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "CommandLine": "cmd.exe /c whoami",
                        "_raw": "EventCode=4688 ComputerName=DESKTOP-VICTIM1 SubjectUserName=victim_user ProcessName=cmd.exe CommandLine='cmd.exe /c whoami'"
                    }
                ]))
            elif "index=pan_logs" in last_human_message and "dest_ip=\"45.33.22.11\"" in last_human_message:
                return MockLLMResponse(json.dumps([
                    {
                        "_time": "2025-12-01T14:30:12.801Z",
                        "index": "pan_logs",
                        "sourcetype": "pan:traffic",
                        "host": "PaloAlto-FW01",
                        "source": "syslog",
                        "action": "allow",
                        "src_ip": "10.67.3.130",
                        "src_port": 51234,
                        "dest_ip": "45.33.22.11",
                        "dest_port": 4444,
                        "proto": "tcp",
                        "app": "unknown",
                        "rule": "OUTBOUND_C2_ALERT",
                        "log_source": "Palo Alto Networks",
                        "_raw": "action=allow src_ip=10.67.3.130 dest_ip=45.33.22.11 proto=tcp app=unknown rule=OUTBOUND_C2_ALERT"
                    }
                ]))
            elif "admin" in last_human_message:
                return MockLLMResponse(json.dumps([
                    {
                        "_time": "2025-12-01T11:00:00.000Z",
                        "index": "windows",
                        "sourcetype": "WinEventLog:Security",
                        "host": "SERVER-001",
                        "source": "WinEventLog",
                        "EventCode": "4624",
                        "TargetUserName": "admin",
                        "LogonType": "10",
                        "Status": "Success",
                        "src_ip": "192.168.1.100",
                        "_raw": "EventCode=4624 TargetUserName=admin LogonType=10 src_ip=192.168.1.100"
                    }
                ]))
            return MockLLMResponse("[]")


    class LLMAPI:
        def get_model(self, tag="cheap"):
            return MockLLM()


class SplunkMock:
    """
    基于 LLM 的动态 Splunk 日志生成器。
    根据 SPL 查询和预设的失陷指标（IOCs）生成模拟 Splunk 日志数据。
    """

    # ==========================================
    # 1. 核心控制配置：失陷指标列表 (IOCs)
    # ==========================================
    COMPROMISED_IOCS = {
        "internal_ips": ["10.67.3.130", "10.10.10.5"],  # 受害者主机
        "attacker_ips": ["192.168.1.100", "45.33.22.11"],  # 攻击源 (内网跳板或外网C2)
        "malicious_users": ["admin", "root", "deploy"],  # 被利用的账号
        "malicious_files": ["cmd.exe", "powershell.exe", "wget", "nc.exe"],
        "hashes": ["a1b2c3d4e5f6...", "deadbeef..."]
    }

    # ==========================================
    # 2. Splunk 数据模型 (Schemas)
    #    定义常见的 index 及其字段、sourcetype 和示例日志，供 LLM 参考。
    # ==========================================
    SPLUNK_SCHEMAS = {
        "windows": {
            "description": "Windows Security Event Logs (Event Codes for login, process creation, etc.)",
            "common_fields": [
                "EventCode", "ComputerName", "SubjectUserName", "TargetUserName",
                "ProcessName", "ParentProcessName", "CommandLine", "LogonType",
                "AuthenticationPackage", "WorkstationName", "NewProcessId",
                "Image", "Hashes", "Signature", "Status", "IpAddress", "Port"
            ],
            "sourcetype": "WinEventLog:Security",
            "example_log": {
                "_time": "2025-12-01T10:00:00.000Z",
                "index": "windows",
                "sourcetype": "WinEventLog:Security",
                "host": "DC01.corp.local",
                "source": "WinEventLog",
                "EventCode": "4624",
                "ComputerName": "DESKTOP-VICTIM1",
                "SubjectUserName": "S-1-5-18",
                "TargetUserName": "victim_user",
                "ProcessName": "C:\\Windows\\System32\\lsass.exe",
                "LogonType": "2",
                "AuthenticationPackage": "Negotiate",
                "WorkstationName": "DESKTOP-VICTIM1",
                "IpAddress": "192.168.1.50",
                "_raw": "EventCode=4624 ComputerName=DESKTOP-VICTIM1 SubjectUserName=S-1-5-18 TargetUserName=victim_user LogonType=2 IpAddress=192.168.1.50 ..."
            }
        },
        "pan_logs": {
            "description": "Palo Alto Networks Firewall Traffic Logs, detailing network connections.",
            "common_fields": [
                "action", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
                "app", "rule", "bytes_in", "bytes_out", "elapsed_time",
                "vsys", "zone_in", "zone_out", "category", "risk_level"
            ],
            "sourcetype": "pan:traffic",
            "example_log": {
                "_time": "2025-12-01T10:05:15.000Z",
                "index": "pan_logs",
                "sourcetype": "pan:traffic",
                "host": "FW-Corp-DMZ",
                "source": "/var/log/pan_traffic.log",
                "action": "allow",
                "src_ip": "10.67.3.130",
                "src_port": "51234",
                "dest_ip": "45.33.22.11",
                "dest_port": "4444",
                "proto": "tcp",
                "app": "unknown",
                "rule": "OUTBOUND_C2_ALERT",
                "bytes_in": 78,
                "bytes_out": 128,
                "_raw": "action=allow src_ip=10.67.3.130 src_port=51234 dest_ip=45.33.22.11 dest_port=4444 proto=tcp app=unknown rule=OUTBOUND_C2_ALERT ..."
            }
        },
        "cloudtrail": {
            "description": "AWS CloudTrail logs, auditing API calls and user activity in AWS.",
            "common_fields": [
                "eventSource", "eventName", "userIdentity.type", "userIdentity.userName",
                "sourceIPAddress", "userAgent", "requestParameters", "responseElements",
                "errorCode", "awsRegion", "eventVersion", "eventTime", "recipientAccountId"
            ],
            "sourcetype": "aws:cloudtrail",
            "example_log": {
                "_time": "2025-12-01T09:15:00.000Z",
                "index": "cloudtrail",
                "sourcetype": "aws:cloudtrail",
                "host": "cloudtrail.amazonaws.com",
                "source": "cloudtrail",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser",
                "userIdentity": {"type": "IAMUser", "userName": "deploy"},
                "sourceIPAddress": "192.168.1.100",
                "awsRegion": "us-east-1",
                "eventVersion": "1.08",
                "eventTime": "2025-12-01T09:15:00Z",
                "_raw": "{\"eventSource\":\"iam.amazonaws.com\", \"eventName\":\"CreateUser\", \"userIdentity\":{\"type\":\"IAMUser\",\"userName\":\"deploy\"}, \"sourceIPAddress\":\"192.168.1.100\", \"awsRegion\":\"us-east-1\", \"eventVersion\":\"1.08\", \"eventTime\":\"2025-12-01T09:15:00Z\"}"
            }
        },
        "zeek": {
            "description": "Zeek (Bro) network security monitor logs, detailing network connections and protocols.",
            "common_fields": [
                "uid", "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p", "proto",
                "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "action",
                "tunnel_parents", "local_orig", "local_resp", "history"
            ],
            "sourcetype": "zeek:conn",
            "example_log": {
                "_time": "2025-12-01T14:30:12.801Z",
                "index": "zeek",
                "sourcetype": "zeek:conn",
                "host": "zeek-sensor-01",
                "source": "/opt/zeek/logs/current/conn.log",
                "uid": "C9a1b2c3d4e5f6a7b",
                "id_orig_h": "10.67.3.130",
                "id_orig_p": 51234,
                "id_resp_h": "45.33.22.11",
                "id_resp_p": 4444,
                "proto": "tcp",
                "service": "null",
                "duration": 2.3,
                "orig_bytes": 78,
                "resp_bytes": 128,
                "conn_state": "SF",
                "action": "allowed",
                "_raw": "uid=C9a1b2c3d4e5f6a7b id_orig_h=10.67.3.130 id_orig_p=51234 id_resp_h=45.33.22.11 id_resp_p=4444 proto=tcp ..."
            }
        }
    }

    # ==========================================
    # 3. 内嵌的 System Prompt
    # ==========================================
    LOG_GEN_SYSTEM_PROMPT = """
# ROLE: You are a Splunk Enterprise Security (ES) Simulator. Your output is read by a program, not a human.

# PRIMARY DIRECTIVE
Your goal is to act as a Splunk database. You will receive a Splunk Processing Language (SPL) query and must return a series of hyper-realistic Splunk log events in a structured JSON list. These events must logically match the SPL query and incorporate the "GROUND TRUTH" IOCs where relevant.

# GROUND TRUTH (Known Malicious Entities)
This is the absolute truth for your simulation. Any query involving these entities is part of a real attack.
{ioc_json}

# SPLUNK DATA MODELS (SCHEMA)
This is your knowledge base of the available Splunk indexes and sourcetypes. When a query uses an index, you MUST generate logs consistent with its schema and example_log if present.
{splunk_schema_json}

# CHAIN OF THOUGHT (Your Internal Process)
1.  **Deconstruct SPL Query**: Analyze the user's SPL query (`User Query: ...`). Identify the target `index`, `sourcetype`, time constraints, keywords, and any filtering/aggregation commands.
2.  **Correlate with Ground Truth**: Does the SPL query's filter (e.g., `dest_ip="45.33.22.11"`) match any "GROUND TRUTH" IOCs?
3.  **Select Data Model**: Based on the `index` or `sourcetype` in the SPL, choose the corresponding schema from the `SPLUNK DATA MODELS`. If an `example_log` exists for the selected schema, use it as a strong reference.
4.  **Generate Log Series**: Create 3-5 log entries that satisfy the SPL query. Adhere to all `LOG REALISM PRINCIPLES`. If the query implies malicious activity (by matching an IOC), the logs should narrate that activity. If not, generate plausible benign logs or an empty list if no results would be found.

# LOG REALISM PRINCIPLES
1.  **Splunk Format**: Each log event MUST be a JSON object containing standard Splunk fields: `_time` (ISO-8601), `index`, `sourcetype`, `host`, `source`, and `_raw`.
2.  **_raw Synchronization**: The `_raw` field MUST be a string that accurately represents the structured key-value pairs (including standard Splunk fields and data model specific fields) in the rest of the JSON object. Avoid JSON string in _raw unless the original log format is JSON. For most logs, it should be a key=value or space-separated string.
3.  **Temporal Progression**: `_time` values must be chronological and close together, formatted as ISO-8601 strings (e.g., "2025-12-01T14:30:10.554Z").
4.  **Field Richness**: Populate fields generously based on the selected `SPLUNK DATA MODELS`. A firewall log must have IPs/ports; a windows log must have EventCodes/ProcessNames.

# CRITICAL OUTPUT REQUIREMENTS
- Your entire response **MUST** be a single, raw JSON string representing a Python list of log objects.
- **DO NOT** include any introductory text, explanations, or markdown fences like ```json ... ```.
- The response must start with `[` and end with `]`. Any deviation will cause a system failure.
- If the SPL query would legitimately return no results, return an empty JSON list: `[]`.
"""

    @staticmethod
    def _extract_json_from_response(raw_text: str) -> List[Dict[str, Any]]:
        """
        从LLM的原始输出中稳健地提取和解析JSON列表。
        """
        # 1. 尝试直接解析整个文本
        try:
            # 假设日志是列表格式
            loaded_json = json.loads(raw_text)
            if isinstance(loaded_json, list):
                return loaded_json
        except json.JSONDecodeError:
            pass  # 如果失败，则继续尝试提取

        # 2. 尝试从Markdown代码块中提取
        match = re.search(r'```json\s*([\s\S]+?)\s*```', raw_text, re.DOTALL)
        if match:
            json_str = match.group(1).strip()
            try:
                loaded_json = json.loads(json_str)
                if isinstance(loaded_json, list):
                    return loaded_json
            except json.JSONDecodeError:
                # 如果代码块内容也不是有效的JSON，则继续
                pass

        # 3. 尝试查找第一个 '[' 和最后一个 ']' 之间的内容
        start_index = raw_text.find('[')
        end_index = raw_text.rfind(']')
        if start_index != -1 and end_index != -1 and start_index < end_index:
            json_str = raw_text[start_index:end_index + 1]
            try:
                loaded_json = json.loads(json_str)
                if isinstance(loaded_json, list):
                    return loaded_json
            except json.JSONDecodeError:
                # 如果这部分内容也不是有效的JSON，则准备抛出最终错误
                pass

        # 4. 如果所有尝试都失败，则抛出异常
        raise json.JSONDecodeError("Failed to find any valid JSON list in the LLM output.", raw_text, 0)

    @staticmethod
    def search(spl_query: str) -> List[Dict[str, Any]]:
        """
        Tool Function: Search simulated Splunk logs using an SPL query.

        Args:
            spl_query: A Splunk Processing Language (SPL) query string.
                       e.g., 'index=windows EventCode=4624 earliest=-1d'
                       e.g., 'index=pan_logs dest_ip="45.33.22.11" | stats count by src_ip'
        """
        print(f"[🔮 Splunk Mock] Generating logs for SPL query: '{spl_query}'")

        # 1. 准备上下文和 Prompt
        ioc_context = json.dumps(SplunkMock.COMPROMISED_IOCS, indent=2)
        splunk_schema_context = json.dumps(SplunkMock.SPLUNK_SCHEMAS, indent=2)

        formatted_system_prompt = SplunkMock.LOG_GEN_SYSTEM_PROMPT.format(
            ioc_json=ioc_context,
            splunk_schema_json=splunk_schema_context
        )

        # 2. 调用 LLM
        response_content = ""
        try:
            llm_api = LLMAPI()
            llm = llm_api.get_model(tag="cheap")  # You might want a "smart" model for SPL parsing
            messages = [
                SystemMessage(content=formatted_system_prompt),
                HumanMessage(content=f"User SPL Query: {spl_query}")
            ]
            response = llm.invoke(messages)
            response_content = response.content

            # 3. 使用稳健的解析方法提取日志
            logs = SplunkMock._extract_json_from_response(response_content)

            print(f"   [✅ Splunk Mock] Generated {len(logs)} logs.")
            return logs

        except (json.JSONDecodeError, ValueError) as e:
            # 在错误详情中包含原始输出以便调试
            raw_output = response_content if response_content else "Response content was empty."
            if isinstance(e, json.JSONDecodeError):
                # e.doc 包含传递给解码器的原始字符串
                raw_output = e.doc

            error_details = f"Model output could not be parsed as a valid JSON list. Raw output: {raw_output}"
            print(f"   [⚠️ Error] Splunk Mock generation failed: {error_details}")
            return [
                {
                    "_time": "N/A",
                    "event": "splunk_log_generation_error",
                    "details": error_details,
                    "spl_query": spl_query
                }
            ]
        except Exception as e:
            print(f"   [⚠️ Error] Splunk Mock generation failed with an unexpected error: {e}")
            return [
                {
                    "_time": "N/A",
                    "event": "splunk_log_generation_error",
                    "details": f"An unexpected error occurred: {e}",
                    "spl_query": spl_query
                }
            ]


# =============================================================================
# 导出给 Agent 绑定的工具函数
# =============================================================================

def splunk_search_tool(
        spl_query: Annotated[
            str, """A Splunk Processing Language (SPL) query string. The query should be specific and well-formed. Example: 'index=pan_logs dest_ip="45.33.22.11" earliest=-1h' Example: 'index=windows EventCode=4688 "powershell.exe" | top limit=10 CommandLine'"""] = None,
) -> List[Dict]:
    """
    Executes a search query against the simulated Splunk SIEM to find security logs.
    """
    # 代理到 Mock 类
    return SplunkMock.search(spl_query)


# =============================================================================
# 测试代码
# =============================================================================
if __name__ == "__main__":
    print("--- Test 1: Malicious Windows Login (IOC Match) ---")
    spl_query_win_bad_user = 'index=windows EventCode=4624 TargetUserName="admin" earliest=-1d'
    logs_win_bad = splunk_search_tool(spl_query_win_bad_user)
    print(json.dumps(logs_win_bad, indent=2, ensure_ascii=False))

    print("\n--- Test 2: Malicious Outbound Connection (IOC Match) ---")
    spl_query_pan_c2 = 'index=pan_logs dest_ip="45.33.22.11" earliest=-1h'
    logs_pan_c2 = splunk_search_tool(spl_query_pan_c2)
    print(json.dumps(logs_pan_c2, indent=2, ensure_ascii=False))

    print("\n--- Test 3: Benign Windows Process Creation (No IOC Match) ---")
    spl_query_win_benign = 'index=windows EventCode=4688 ProcessName="explorer.exe" earliest=-1d'
    logs_win_benign = splunk_search_tool(spl_query_win_benign)
    print(json.dumps(logs_win_benign, indent=2, ensure_ascii=False))

    print("\n--- Test 4: Query for a non-existent index (Should return empty or error) ---")
    spl_query_non_existent = 'index=nonexistent_logs some_field="value"'
    logs_non_existent = splunk_search_tool(spl_query_non_existent)
    print(json.dumps(logs_non_existent, indent=2, ensure_ascii=False))
