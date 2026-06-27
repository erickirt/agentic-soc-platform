import ipaddress
import re
from urllib.parse import quote

import httpx

from apps.artifacts.models import ArtifactType
from apps.settings.runtime_config import get_otx_config
from integrations.threat_intel.models import TIProviderResult

MOCK_PROVIDER_NAME = "MockTIProvider"
OTX_PROVIDER_NAME = "AlienVaultOTX"
MAX_PULSE_SUMMARIES = 5
MAX_LIST_ITEMS = 12
SUPPORTED_TYPES = {
    ArtifactType.IP_ADDRESS,
    ArtifactType.HOSTNAME,
    ArtifactType.URL_STRING,
    ArtifactType.HASH,
    ArtifactType.EMAIL_ADDRESS,
}
MALICIOUS_KEYWORDS = {"evil", "malware", "phishing", "suspicious"}


class BaseThreatIntelProvider:
    name = ""

    def query(self, indicator, *, artifact_type):
        raise NotImplementedError


class MockThreatIntelProvider(BaseThreatIntelProvider):
    name = MOCK_PROVIDER_NAME

    def query(self, indicator, *, artifact_type):
        artifact_type = _artifact_type_value(artifact_type)
        indicator = str(indicator or "").strip()
        if artifact_type not in SUPPORTED_TYPES:
            return TIProviderResult(
                indicator=indicator,
                indicator_type=artifact_type,
                provider=self.name,
                error="Unsupported artifact type.",
            )

        lowered = indicator.lower()
        if artifact_type == ArtifactType.IP_ADDRESS and _is_private_ip(indicator):
            return TIProviderResult(
                indicator=indicator,
                indicator_type=artifact_type,
                provider=self.name,
                risk_level="low",
                reputation_score=5,
                is_malicious=False,
                tags=["private"],
                raw={"source": self.name, "rule": "private-ip"},
            )

        if any(keyword in lowered for keyword in MALICIOUS_KEYWORDS):
            return TIProviderResult(
                indicator=indicator,
                indicator_type=artifact_type,
                provider=self.name,
                risk_level="high",
                reputation_score=95,
                is_malicious=True,
                tags=[keyword for keyword in MALICIOUS_KEYWORDS if keyword in lowered],
                raw={"source": self.name, "rule": "keyword-match"},
            )

        risk_level = "medium" if artifact_type == ArtifactType.HASH else "low"
        return TIProviderResult(
            indicator=indicator,
            indicator_type=artifact_type,
            provider=self.name,
            risk_level=risk_level,
            reputation_score=50 if risk_level == "medium" else 10,
            is_malicious=False,
            tags=["mock"],
            raw={"source": self.name, "rule": "default"},
        )


class AlienVaultOTXProvider(BaseThreatIntelProvider):
    name = OTX_PROVIDER_NAME

    def __init__(self, *, api_key=None, base_url=None, proxy=None, timeout=None, http_client=None):
        config = get_otx_config()
        self.api_key = config["api_key"] if api_key is None else api_key
        self.base_url = (base_url or config["base_url"]).rstrip("/")
        self.proxy = config["proxy"] if proxy is None else proxy
        self.timeout = config["timeout_seconds"] if timeout is None else timeout
        self.http_client = http_client

    def query(self, indicator, *, artifact_type):
        artifact_type = _artifact_type_value(artifact_type)
        indicator = str(indicator or "").strip()
        endpoint = self._endpoint_for(indicator, artifact_type)
        if endpoint["error"]:
            return TIProviderResult(
                indicator=indicator,
                indicator_type=endpoint["indicator_type"],
                provider=self.name,
                error=endpoint["error"],
            )
        if not self.api_key:
            return TIProviderResult(
                indicator=indicator,
                indicator_type=endpoint["indicator_type"],
                provider=self.name,
                error="AlienVault OTX API key is not configured.",
            )

        response = self._request_json(endpoint["path"])
        if response.get("error"):
            return TIProviderResult(
                indicator=indicator,
                indicator_type=endpoint["indicator_type"],
                provider=self.name,
                raw=response,
                error=response["error"],
            )

        if endpoint["indicator_type"] in {"ip", "file"}:
            response["reputation_score"] = self.calculate_reputation_score(response)
        return self.summarize_result(response, endpoint["indicator_type"], indicator)

    def _endpoint_for(self, indicator, artifact_type):
        if artifact_type == ArtifactType.IP_ADDRESS:
            try:
                ip = ipaddress.ip_address(indicator)
            except ValueError:
                return {"path": "", "indicator_type": "ip", "error": "Invalid IPv4 address."}
            if ip.version != 4:
                return {"path": "", "indicator_type": "ip", "error": "Only IPv4 indicators are supported."}
            return {"path": f"/indicators/IPv4/{indicator}/general", "indicator_type": "ip", "error": None}

        if artifact_type == ArtifactType.URL_STRING:
            if not _looks_like_url(indicator):
                return {"path": "", "indicator_type": "url", "error": "Invalid URL indicator."}
            return {
                "path": f"/indicators/url/{quote(indicator, safe='')}/general",
                "indicator_type": "url",
                "error": None,
            }

        if artifact_type == ArtifactType.HASH:
            if not re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", indicator):
                return {
                    "path": "",
                    "indicator_type": "file",
                    "error": "Invalid hash. Must be MD5, SHA1, or SHA256 hex.",
                }
            return {"path": f"/indicators/file/{indicator}/general", "indicator_type": "file", "error": None}

        return {
            "path": "",
            "indicator_type": artifact_type or "unknown",
            "error": f"Unsupported artifact type for AlienVault OTX: {artifact_type}",
        }

    def _request_json(self, path):
        headers = {
            "accept": "application/json",
            "X-OTX-API-KEY": self.api_key,
        }
        url = f"{self.base_url}{path}"
        try:
            if self.http_client is None:
                client_kwargs = {"timeout": self.timeout}
                if self.proxy:
                    client_kwargs["proxy"] = self.proxy
                with httpx.Client(**client_kwargs) as client:
                    response = client.get(url, headers=headers)
            else:
                response = self.http_client.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            return {"error": f"OTX HTTP {exc.response.status_code}: {exc.response.text}"}
        except httpx.HTTPError as exc:
            return {"error": f"OTX request failed: {type(exc).__name__}: {exc}"}
        except ValueError as exc:
            return {"error": f"OTX response is not valid JSON: {exc}"}

    def summarize_result(self, attributes, indicator_type, indicator):
        if attributes.get("error"):
            return TIProviderResult(
                indicator=indicator,
                indicator_type=indicator_type,
                provider=self.name,
                raw=attributes,
                error=attributes["error"],
            )

        pulse_info = attributes.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        reputation_score = attributes.get("reputation_score")
        pulse_count = pulse_info.get("count", len(pulses))
        risk_level = self._risk_level(reputation_score, pulse_count)
        validation = self._compact_named_items(attributes.get("validation") or [])
        false_positive = self._compact_named_items(attributes.get("false_positive") or [])
        raw = {
            "source": self.name,
            "pulse_count": pulse_count,
            "validation": validation,
            "false_positive": false_positive,
        }

        return TIProviderResult(
            indicator=indicator,
            indicator_type=indicator_type,
            provider=self.name,
            risk_level=risk_level,
            reputation_score=reputation_score,
            is_malicious=risk_level in {"high", "medium"},
            tags=self._limit_list(self._unique_items(tag for pulse in pulses for tag in pulse.get("tags", []))),
            attack_techniques=self._limit_list(self._extract_attack_techniques(pulses)),
            malware_families=self._limit_list(self._extract_related_values(pulse_info, "malware_families")),
            adversaries=self._limit_list(self._extract_related_values(pulse_info, "adversary")),
            industries=self._limit_list(self._extract_related_values(pulse_info, "industries")),
            pulses=self._compact_pulses(pulses),
            network_context=self._network_context(attributes),
            raw=raw,
        )

    @staticmethod
    def _unique_items(items):
        unique = []
        for item in items:
            if item and item not in unique:
                unique.append(item)
        return unique

    @staticmethod
    def _limit_list(items, limit=MAX_LIST_ITEMS):
        return items[:limit]

    @classmethod
    def _extract_attack_techniques(cls, pulses):
        techniques = []
        for pulse in pulses:
            for attack in pulse.get("attack_ids", []) or []:
                display_name = attack.get("display_name") or attack.get("name") or attack.get("id")
                if display_name:
                    techniques.append(display_name)
        return cls._unique_items(techniques)

    @classmethod
    def _extract_related_values(cls, pulse_info, key):
        related = pulse_info.get("related") or {}
        values = []
        for source in ("alienvault", "other"):
            values.extend((related.get(source) or {}).get(key, []) or [])
        return cls._unique_items(values)

    @classmethod
    def _compact_named_items(cls, items):
        compact = []
        for item in items:
            if isinstance(item, dict):
                value = item.get("name") or item.get("source") or item.get("description")
                if value:
                    compact.append(value)
            elif item:
                compact.append(item)
        return cls._limit_list(cls._unique_items(compact))

    @classmethod
    def _compact_pulses(cls, pulses):
        compact = []
        for pulse in pulses[:MAX_PULSE_SUMMARIES]:
            compact.append(
                {
                    "name": pulse.get("name"),
                    "description": pulse.get("description"),
                    "tags": cls._limit_list(pulse.get("tags", [])),
                    "attack_techniques": cls._limit_list(cls._extract_attack_techniques([pulse])),
                    "malware_families": cls._limit_list(pulse.get("malware_families", []) or []),
                    "adversary": pulse.get("adversary"),
                    "created": pulse.get("created"),
                    "modified": pulse.get("modified"),
                    "tlp": pulse.get("TLP"),
                }
            )
        return compact

    @staticmethod
    def _network_context(attributes):
        context = {}
        for field in ("asn", "country_name", "country_code", "region", "city"):
            if attributes.get(field):
                context[field] = attributes[field]
        return context or None

    @staticmethod
    def _risk_level(reputation_score, pulse_count):
        score = reputation_score or 0
        if score >= 50 or pulse_count >= 5:
            return "high"
        if score >= 20 or pulse_count > 0:
            return "medium"
        return "low"

    @staticmethod
    def calculate_reputation_score(attributes):
        score = 0
        pulse_info = attributes.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])
        score -= pulse_count * 10

        related = pulse_info.get("related", {})
        malware_families = (related.get("alienvault", {}).get("malware_families", []) or []) + (
            related.get("other", {}).get("malware_families", []) or []
        )
        score -= len(malware_families) * 15

        adversaries = (related.get("alienvault", {}).get("adversary", []) or []) + (
            related.get("other", {}).get("adversary", []) or []
        )
        score -= len(adversaries) * 12

        for validation in attributes.get("validation", []):
            if validation.get("name") == "whitelist":
                score += 20
            elif validation.get("name") == "blacklist":
                score -= 25

        false_positive = attributes.get("false_positive", [])
        if false_positive:
            score += len(false_positive) * 10

        for pulse in pulses:
            for tag in pulse.get("tags", []):
                if tag.lower() in {"malware", "trojan", "backdoor", "botnet", "apt", "exploit"}:
                    score -= 8

        return -score


def _artifact_type_value(artifact_type):
    return artifact_type.value if hasattr(artifact_type, "value") else str(artifact_type)


def _is_private_ip(value):
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _looks_like_url(value):
    if re.match(r"^(https?://|ftp://|www\.)", value, re.IGNORECASE):
        return True
    return "." in value and "/" in value


def get_providers():
    config = get_otx_config()
    if config["enabled"] and config["api_key"]:
        return {OTX_PROVIDER_NAME: AlienVaultOTXProvider()}
    return {MOCK_PROVIDER_NAME: MockThreatIntelProvider()}
