import re
from typing import List, Dict, Optional, Any

# 扩展后的模拟 CMDB 数据，键为 CI ID
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


class CMDB_Mock:
    """
    模拟企业级CMDB接口，扩展了多维度CI数据查找逻辑。
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

    # A. 标识符精确检索 (重构为支持多标识符)
    def get_ci_context(self, identifier_type: str, identifier_value: str) -> Dict[str, Any]:
        """
        根据精确标识符检索单个CI的完整上下文信息。
        API: GET /v1/ci/search
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

    # B. 模糊/部分匹配检索
    def fuzzy_search_ci(self, partial_hostname: Optional[str] = None, regex_pattern: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        根据部分主机名或正则表达式检索匹配的CI列表。
        API: GET /v1/ci/fuzzy_search
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

    # C. 软件版本检索
    def get_cis_by_software(self, software_name: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        检索运行特定软件或软件版本的CI列表（现在包括服务器、PC、云实例）。
        API: GET /v1/ci/by_software
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

    # D. 开放端口检索
    def get_cis_by_port(self, port_number: int, protocol: str = "TCP") -> List[Dict[str, Any]]:
        """
        检索开放了特定端口和协议的CI列表。
        API: GET /v1/ci/by_port
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

    # E. 业务服务查询
    def get_cis_by_service(self, service_id: str) -> List[Dict[str, Any]]:
        """
        检索支撑特定业务服务的所有CI列表。
        API: GET /v1/ci/by_service
        """
        if not service_id:
            raise ValueError("Service ID cannot be empty.")

        matching_cis = []
        for ci_data in self._data.values():
            if ci_data.get("service_id") == service_id and ci_data.get("ci_type") not in ["Employee", "DomainName"]:
                matching_cis.append({
                    "ci_id": ci_data.get("ci_id"),
                    "ip_address": ci_data.get("ip_address"),
                    "ci_type": ci_data.get("ci_type"),
                    "business_criticality": ci_data.get("business_criticality")
                })

        return matching_cis

    # F. 用户/责任人查询
    def get_cis_by_user(self, user_id: str) -> List[Dict[str, Any]]:
        """
        检索由特定用户主要使用的或负责的CI列表。
        API: GET /v1/ci/by_user
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


# 实例化模拟器以便进行测试
cmdb_simulator = CMDB_Mock(EXTENDED_CMDB_DATA)

try:
    print("--- 扩展后的 C. 软件检索 (java 11) ---")
    java_cis = cmdb_simulator.get_cis_by_software(software_name="java", version="11")
    print(java_cis)

    print("\n--- 扩展后的 B. 模糊匹配 (查找所有 AWS EC2 实例) ---")
    cloud_cis = cmdb_simulator.fuzzy_search_ci(regex_pattern=r"aws-")
    print(cloud_cis)

except (ValueError, LookupError) as e:
    # 根据定制化要求，异常直接 raise
    raise
