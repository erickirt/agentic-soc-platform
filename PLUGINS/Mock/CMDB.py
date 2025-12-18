import re
from typing import List, Dict, Optional, Any, Annotated

# 扩展后的模拟 CMDB 数据，键为 CI ID (保持与上次一致)
EXTENDED_CMDB_DATA = {
    # 1. 核心服务器 CI (不变)
    "SRV-WEB-001": {
        "ci_id": "SRV-WEB-001", "ci_type": "Server", "hostname": "prod-web-01", "ip_address": ["192.168.10.5", "10.10.10.5"],
        "ci_status": "Deployed/Active", "business_criticality": "High", "service_id": "SVC-ECOM-001",
        "owner_team": "WebOps Team", "network_zone": "DMZ", "os_version": "RHEL 8.6",
        "hardware_model": "Dell PowerEdge R640", "installed_software": [{"name": "nginx", "version": "1.20.1"}, {"name": "php-fpm", "version": "7.4"}],
        "open_ports": [{"port": 80, "protocol": "TCP"}, {"port": 443, "protocol": "TCP"}], "primary_user_id": None
    },
    # 2. 数据库 CI (不变)
    "APP-DB-003": {
        "ci_id": "APP-DB-003", "ci_type": "Database", "hostname": "prod-db-03", "ip_address": ["172.16.0.22"],
        "ci_status": "Deployed/Active", "business_criticality": "Critical", "service_id": "SVC-ECOM-001",
        "owner_team": "DBA Team", "network_zone": "Internal Prod",
        "installed_software": [{"name": "mysql", "version": "8.0.27"}],
        "open_ports": [{"port": 3306, "protocol": "TCP"}], "primary_user_id": "user_a"
    },
    # 3. 员工 CI (不变)
    "EMP-0010": {
        "ci_id": "EMP-0010", "ci_type": "Employee", "employee_name": "张三", "user_id": "user_a",
        "department": "IT Operations", "job_title": "Database Administrator", "access_level": "High/Critical"
    },
    # 4. PC/工作站 CI (不变)
    "PC-HR-04": {
        "ci_id": "PC-HR-04", "ci_type": "Workstation", "hostname": "hr-pc-04", "ip_address": ["10.0.1.10"],
        "ci_status": "Deployed/Active", "business_criticality": "Low", "service_id": "SVC-HR-003",
        "owner_team": "HR Team", "os_version": "Windows 10", "mac_address": "00:1A:2B:3C:4D:5E",
        "installed_software": [{"name": "office", "version": "2021"}], "primary_user_id": "user_b"
    },
    # 5. 域名 CI (不变)
    "DNS-ECOM-MAIN": {
        "ci_id": "DNS-ECOM-MAIN", "ci_type": "DomainName", "domain_name": "example-ecommerce.com",
        "ci_status": "Active", "business_criticality": "Critical", "owner_team": "Marketing",
        "dns_registrar": "GoDaddy", "expiration_date": "2026-10-10", "related_ip": ["192.168.10.5"]
    },
    # --- 新增类型 6: 网络设备 (NetworkDevice) ---
    "FW-DMZ-01": {
        "ci_id": "FW-DMZ-01", "ci_type": "NetworkDevice", "hostname": "dmz-fw-01",
        "ip_address": ["192.168.10.1", "10.10.10.1"], "ci_status": "Active",
        "business_criticality": "Critical", "owner_team": "NetSec", "device_type": "Firewall",
        "vendor": "Cisco", "os_version": "ASA 9.1", "location": "DC-Shanghai",
        "management_ip": "172.31.0.1"
    },
    "RTR-CORE-02": {
        "ci_id": "RTR-CORE-02", "ci_type": "NetworkDevice", "hostname": "core-rtr-02",
        "ip_address": ["172.16.255.2"], "ci_status": "Active", "business_criticality": "High",
        "owner_team": "Network", "device_type": "Router", "vendor": "Juniper",
        "os_version": "Junos 18.4", "location": "DC-Beijing"
    },
    "SW-PROD-05": {
        "ci_id": "SW-PROD-05", "ci_type": "NetworkDevice", "hostname": "prod-sw-05",
        "ip_address": ["172.16.1.5"], "ci_status": "Active", "business_criticality": "Medium",
        "owner_team": "Network", "device_type": "Switch", "vendor": "Huawei",
        "os_version": "VRP 5.1", "location": "DC-Shanghai"
    },
    "LB-EXT-01": {
        "ci_id": "LB-EXT-01", "ci_type": "NetworkDevice", "hostname": "ext-lb-01",
        "ip_address": ["103.20.10.1"], "ci_status": "Active", "business_criticality": "Critical",
        "owner_team": "WebOps", "device_type": "LoadBalancer", "vendor": "F5",
        "os_version": "TMOS 14.1", "location": "Cloud POP"
    },
    "VPN-GATE-03": {
        "ci_id": "VPN-GATE-03", "ci_type": "NetworkDevice", "hostname": "vpn-gate-03",
        "ip_address": ["203.0.113.1"], "ci_status": "Active", "business_criticality": "Medium",
        "owner_team": "NetSec", "device_type": "VPN Concentrator", "vendor": "Palo Alto",
        "os_version": "PAN-OS 10.0", "location": "DC-Shanghai"
    },

    # --- 新增类型 7: 云服务实例 (CloudInstance) ---
    "EC2-PROD-A1": {
        "ci_id": "EC2-PROD-A1", "ci_type": "CloudInstance", "hostname": "aws-app-a1",
        "ip_address": ["172.31.5.10"], "ci_status": "Running", "business_criticality": "High",
        "service_id": "SVC-ECOM-001", "owner_team": "CloudOps", "cloud_provider": "AWS",
        "region": "us-east-1", "instance_type": "t3.medium", "os_version": "Amazon Linux 2",
        "installed_software": [{"name": "java", "version": "11"}, {"name": "tomcat", "version": "9"}],
        "primary_user_id": None
    },
    "GCE-DEV-B2": {
        "ci_id": "GCE-DEV-B2", "ci_type": "CloudInstance", "hostname": "gcp-test-b2",
        "ip_address": ["10.128.0.5"], "ci_status": "Stopped", "business_criticality": "Low",
        "service_id": "SVC-DEV-002", "owner_team": "Dev Team", "cloud_provider": "GCP",
        "region": "asia-east1", "instance_type": "e2-small", "os_version": "Debian 10"
    },
    "AZR-ANL-C3": {
        "ci_id": "AZR-ANL-C3", "ci_type": "CloudInstance", "hostname": "azr-etl-c3",
        "ip_address": ["40.1.1.1"], "ci_status": "Running", "business_criticality": "Medium",
        "service_id": "SVC-ANALYTICS-004", "owner_team": "Data Team", "cloud_provider": "Azure",
        "region": "East Asia", "instance_type": "Standard D4s v3", "os_version": "Windows Server 2019"
    },
    "EC2-DR-04": {
        "ci_id": "EC2-DR-04", "ci_type": "CloudInstance", "hostname": "aws-dr-04",
        "ip_address": ["172.31.20.10"], "ci_status": "Running", "business_criticality": "High",
        "service_id": "SVC-ECOM-001", "owner_team": "CloudOps", "cloud_provider": "AWS",
        "region": "ap-southeast-2", "instance_type": "t3.medium", "os_version": "Amazon Linux 2"
    },
    "GCE-ML-05": {
        "ci_id": "GCE-ML-05", "ci_type": "CloudInstance", "hostname": "gcp-ml-worker",
        "ip_address": ["10.128.0.6"], "ci_status": "Running", "business_criticality": "Medium",
        "service_id": "SVC-AI-005", "owner_team": "AI Team", "cloud_provider": "GCP",
        "region": "us-central1", "instance_type": "n1-standard-8", "os_version": "CentOS 7"
    }
}


class CMDB(object):
    """
    模拟企业级CMDB接口，专注于提供给SOC的上下文检索功能。
    这个类旨在为LLM Agent提供可靠的工具接口，用于安全事件响应和调查。
    """

    def __init__(self, data: Dict[str, Any]):
        """
        初始化CMDB模拟器，构建多重索引以支持高效查找。
        """
        self._data = data
        self._ip_map = {}
        self._hostname_map = {}
        self._mac_map = {}

        # 构建索引，以便通过 IP、Hostname 等快速查找 CI ID
        for ci_id, ci in data.items():
            ci["ci_id"] = ci_id  # 确保 ci_id 存在于每个CI中

            # 索引 IP 地址 (支持多IP)
            for ip in ci.get("ip_address", []):
                self._ip_map[ip] = ci_id

            # 索引 Hostname
            if ci.get("hostname"):
                self._hostname_map[ci["hostname"]] = ci_id

            # 索引 MAC 地址
            if ci.get("mac_address"):
                self._mac_map[ci["mac_address"]] = ci_id

    def _find_ci(self, identifier_type: str, identifier_value: str) -> Optional[Dict[str, Any]]:
        """内部方法：根据标识符查找CI数据，返回完整的CI字典"""
        ci_id = None
        identifier_value = identifier_value.strip()

        if identifier_type == "ip_address":
            ci_id = self._ip_map.get(identifier_value)
        elif identifier_type == "hostname":
            ci_id = self._hostname_map.get(identifier_value)
        elif identifier_type == "mac_address":
            ci_id = self._mac_map.get(identifier_value)
        elif identifier_type == "ci_id":
            ci_id = identifier_value

        return self._data.get(ci_id) if ci_id else None

    # --- 1. 核心通用检索接口 ---

    def get_ci_context(self,
                       identifier_type: Annotated[str, "用于查询的标识符类型，接受 'ip_address', 'hostname', 'mac_address', 'ci_id' 或 'user_id'"],
                       identifier_value: Annotated[str, "标识符的具体值，例如 '192.168.10.5' 或 'prod-web-01'"]
                       ) -> Annotated[Dict[str, Any], "匹配到的单个CI的完整字典数据，包含业务关键性、所属团队等数百个属性。"]:
        """
        [A. 标识符精确检索]：根据精确标识符（IP、主机名、CI ID 或用户 ID）检索单个配置项（CI）的完整上下文信息。
        该接口用于在安全事件发生时，快速将报警中的技术指标关联到具体的业务资产。
        如果找不到CI，则抛出 LookupError。
        """
        if not identifier_type or not identifier_value:
            raise ValueError("Identifier type and value cannot be empty.")

        ci_data = self._find_ci(identifier_type, identifier_value)

        if not ci_data:
            # 增加对员工CI的查找支持
            if identifier_type == "user_id":
                for ci_data in self._data.values():
                    if ci_data.get("ci_type") == "Employee" and ci_data.get("user_id") == identifier_value:
                        return ci_data

            raise LookupError(f"CI not found for {identifier_type}: {identifier_value}")

        return ci_data

    def fuzzy_search_ci(self,
                        partial_hostname: Annotated[Optional[str], "部分主机名片段，例如 'prod-'。如果提供，将进行部分匹配。"] = None,
                        regex_pattern: Annotated[Optional[str], "用于高级匹配的正则表达式"] = None
                        ) -> Annotated[List[Dict[str, Any]], "匹配到的CI列表，仅返回 CI ID、CI 类型、主机名和业务关键性。"]:
        """
        [B. 模糊/部分匹配检索]：根据部分主机名或正则表达式检索匹配的配置项（CI）列表。
        该接口用于在资产名称不完整或需要按特定模式查找时，快速确定资产范围（如查找所有 AWS EC2 实例）。
        如果 partial_hostname 和 regex_pattern 均未提供，则抛出 ValueError。
        """
        if not partial_hostname and not regex_pattern:
            raise ValueError("Either partial_hostname or regex_pattern must be provided.")

        matching_cis = []

        for ci_data in self._data.values():
            hostname = ci_data.get("hostname", ci_data.get("ci_id", ""))
            match = False

            if partial_hostname and partial_hostname.lower() in hostname.lower():
                match = True

            if regex_pattern:
                try:
                    if hostname and re.search(regex_pattern, hostname):
                        match = True
                except re.error as e:
                    raise ValueError(f"Invalid regular expression: {e}")

            if match:
                matching_cis.append({
                    "ci_id": ci_data.get("ci_id"),
                    "ci_type": ci_data.get("ci_type"),
                    "business_criticality": ci_data.get("business_criticality"),
                    "hostname": hostname
                })

        return matching_cis

    # --- 2. 软件/端口关联检索接口 ---

    def get_cis_by_software(self,
                            software_name: Annotated[str, "要查找的软件名称，例如 'nginx' 或 'java'"],
                            version: Annotated[Optional[str], "可选的软件版本号，例如 '11' 或 '1.20.1'。如果未提供，则匹配所有版本。"] = None
                            ) -> Annotated[List[Dict[str, Any]], "运行指定软件的CI列表，包含CI ID、IP地址、CI类型和业务关键性。"]:
        """
        [C. 软件版本检索]：检索运行特定软件或软件版本的配置项（CI）列表。
        该接口用于漏洞管理流程，快速确定哪些资产受到已知软件漏洞的影响（如 Log4j、特定版本的 Tomcat）。
        """
        if not software_name:
            raise ValueError("Software name cannot be empty.")

        matching_cis = []
        for ci_data in self._data.values():
            software_list = ci_data.get("installed_software", [])
            for software in software_list:
                name_match = software["name"].lower() == software_name.lower()
                version_match = (version is None or software["version"] == version)

                if name_match and version_match:
                    matching_cis.append({
                        "ci_id": ci_data.get("ci_id"),
                        "ip_address": ci_data.get("ip_address"),
                        "ci_type": ci_data.get("ci_type"),
                        "business_criticality": ci_data.get("business_criticality")
                    })
                    break

        return matching_cis

    def get_cis_by_port(self,
                        port_number: Annotated[int, "要查找的端口号，例如 22 或 3306"],
                        protocol: Annotated[str, "端口协议，例如 'TCP' 或 'UDP'，默认为 'TCP'"] = "TCP"
                        ) -> Annotated[List[Dict[str, Any]], "开放指定端口和协议的CI列表，包含CI ID、IP地址和网络区域。"]:
        """
        [D. 开放端口检索]：检索开放了特定端口和协议的配置项（CI）列表。
        该接口用于安全审计，快速识别配置错误或未经授权对外开放服务的资产。
        """
        if not isinstance(port_number, int) or port_number <= 0:
            raise ValueError("Invalid port number.")

        matching_cis = []
        for ci_data in self._data.values():
            ports = ci_data.get("open_ports", [])
            for port_info in ports:
                if port_info["port"] == port_number and port_info["protocol"].upper() == protocol.upper():
                    matching_cis.append({
                        "ci_id": ci_data.get("ci_id"),
                        "ip_address": ci_data.get("ip_address"),
                        "network_zone": ci_data.get("network_zone")
                    })
                    break

        return matching_cis

    # --- 3. 业务服务关联检索接口 ---

    def get_cis_by_service(self,
                           service_id: Annotated[str, "要查询的业务服务ID，例如 'SVC-ECOM-001'"]
                           ) -> Annotated[List[Dict[str, Any]], "支撑该业务服务的所有底层CI列表，包含CI ID、IP地址、CI类型和业务关键性。"]:
        """
        [E. 业务服务查询]：检索支撑特定关键业务服务的所有底层配置项（CI）列表。
        该接口用于高级影响分析，当业务服务报警时，快速找出所有相关的服务器、数据库和云实例。
        """
        if not service_id:
            raise ValueError("Service ID cannot be empty.")

        matching_cis = []
        for ci_data in self._data.values():
            # 排除人员和域名，只关注技术资产
            if ci_data.get("service_id") == service_id and ci_data.get("ci_type") not in ["Employee", "DomainName"]:
                matching_cis.append({
                    "ci_id": ci_data.get("ci_id"),
                    "ip_address": ci_data.get("ip_address"),
                    "ci_type": ci_data.get("ci_type"),
                    "business_criticality": ci_data.get("business_criticality")
                })

        return matching_cis

    def get_cis_by_user(self,
                        user_id: Annotated[str, "要查询的用户 ID，例如 'user_a'"]
                        ) -> Annotated[List[Dict[str, Any]], "与该用户关联的所有CI列表，包含员工档案、主要使用的PC/工作站或主要负责的服务器。"]:
        """
        [F. 用户/责任人查询]：检索由特定用户主要使用的或负责的所有配置项（CI）列表。
        该接口用于用户相关的安全事件（如钓鱼、凭证泄露），快速定位用户的所有相关资产进行隔离或取证。
        如果找不到关联CI或用户档案，则抛出 LookupError。
        """
        if not user_id:
            raise ValueError("User ID cannot be empty.")

        matching_cis = []
        found_profile = False

        for ci_data in self._data.values():
            # 查找员工档案
            if ci_data.get("ci_type") == "Employee" and ci_data.get("user_id") == user_id:
                matching_cis.append({
                    "ci_id": ci_data.get("ci_id"),
                    "ci_type": "Employee Profile",
                    "employee_name": ci_data.get("employee_name"),
                    "user_role": "Self"
                })
                found_profile = True

            # 查找资产 (PC, DB, etc.)
            if ci_data.get("primary_user_id") == user_id:
                matching_cis.append({
                    "ci_id": ci_data.get("ci_id"),
                    "ci_type": ci_data.get("ci_type"),
                    "hostname": ci_data.get("hostname", ci_data.get("ci_id")),
                    "user_role": "Primary User"
                })

        if not matching_cis and not found_profile:
            raise LookupError(f"No CI found associated with user_id: {user_id}")

        return matching_cis


# 1. 创建 CMDB 实例
cmdb_instance = CMDB(EXTENDED_CMDB_DATA)


# 2. 将实例方法绑定到全局函数变量，供 LangChain Agent 使用。
# 这种方法是最优的，因为它保留了 Annotated Type Hints 和 Docstrings。

def get_ci_context_tool(
        identifier_type: Annotated[str, "用于查询的标识符类型，接受 'ip_address', 'hostname', 'mac_address', 'ci_id' 或 'user_id'"],
        identifier_value: Annotated[str, "标识符的具体值，例如 '192.168.10.5' 或 'prod-web-01'"]
) -> Annotated[Dict[str, Any], "匹配到的单个CI的完整字典数据，包含业务关键性、所属团队等数百个属性。"]:
    """
    根据精确标识符（IP、主机名、CI ID 或用户 ID）检索单个配置项（CI）的完整上下文信息。
    该接口用于在安全事件发生时，快速将报警中的技术指标关联到具体的业务资产。
    """
    return cmdb_instance.get_ci_context(identifier_type, identifier_value)


def fuzzy_search_ci_tool(
        partial_hostname: Annotated[Optional[str], "部分主机名片段，例如 'prod-'。如果提供，将进行部分匹配。"] = None,
        regex_pattern: Annotated[Optional[str], "用于高级匹配的正则表达式，例如 'aws-\d+'。与 partial_hostname 二选一。"] = None
) -> Annotated[List[Dict[str, Any]], "匹配到的CI列表，仅返回 CI ID、CI 类型、主机名和业务关键性。"]:
    """
    根据部分主机名或正则表达式检索匹配的配置项（CI）列表。
    该接口用于在资产名称不完整或需要按特定模式查找时，快速确定资产范围（如查找所有 AWS EC2 实例）。
    """
    return cmdb_instance.fuzzy_search_ci(partial_hostname, regex_pattern)


def get_cis_by_software_tool(
        software_name: Annotated[str, "要查找的软件名称，例如 'nginx' 或 'java'"],
        version: Annotated[Optional[str], "可选的软件版本号，例如 '11' 或 '1.20.1'。如果未提供，则匹配所有版本。"] = None
) -> Annotated[List[Dict[str, Any]], "运行指定软件的CI列表，包含CI ID、IP地址、CI类型和业务关键性。"]:
    """
    检索运行特定软件或软件版本的配置项（CI）列表。
    该接口用于漏洞管理流程，快速确定哪些资产受到已知软件漏洞的影响。
    """
    return cmdb_instance.get_cis_by_software(software_name, version)


def get_cis_by_port_tool(
        port_number: Annotated[int, "要查找的端口号，例如 22 或 3306"],
        protocol: Annotated[str, "端口协议，例如 'TCP' 或 'UDP'，默认为 'TCP'"] = "TCP"
) -> Annotated[List[Dict[str, Any]], "开放指定端口和协议的CI列表，包含CI ID、IP地址和网络区域。"]:
    """
    检索开放了特定端口和协议的配置项（CI）列表。
    该接口用于安全审计，快速识别配置错误或未经授权对外开放服务的资产。
    """
    return cmdb_instance.get_cis_by_port(port_number, protocol)


def get_cis_by_service_tool(
        service_id: Annotated[str, "要查询的业务服务ID，例如 'SVC-ECOM-001'"]
) -> Annotated[List[Dict[str, Any]], "支撑该业务服务的所有底层CI列表，包含CI ID、IP地址、CI类型和业务关键性。"]:
    """
    检索支撑特定关键业务服务的所有底层配置项（CI）列表。
    该接口用于高级影响分析，当业务服务报警时，快速找出所有相关的服务器、数据库和云实例。
    """
    return cmdb_instance.get_cis_by_service(service_id)


def get_cis_by_user_tool(
        user_id: Annotated[str, "要查询的用户 ID，例如 'user_a'"]
) -> Annotated[List[Dict[str, Any]], "与该用户关联的所有CI列表，包含员工档案、主要使用的PC/工作站或主要负责的服务器。"]:
    """
    检索由特定用户主要使用的或负责的所有配置项（CI）列表。
    该接口用于用户相关的安全事件（如钓鱼、凭证泄露），快速定位用户的所有相关资产进行隔离或取证。
    """
    return cmdb_instance.get_cis_by_user(user_id)



