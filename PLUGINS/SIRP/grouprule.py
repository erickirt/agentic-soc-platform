import hashlib
from datetime import datetime, timezone
from enum import StrEnum
from typing import List, Dict, Any, Optional, Union

from pydantic import BaseModel, Field


class CorrelationStrategy(StrEnum):
    BY_ACTOR = "by_actor"
    BY_TARGET = "by_target"
    BY_ACTOR_AND_TARGET = "by_actor_and_target"
    BY_RULE = "by_rule"
    BY_CUSTOM_FIELDS = "by_custom_fields"


class CorrelationConfig(BaseModel):
    rule_id: str = Field(description="规则ID，用于区分不同类型的告警")
    strategy: CorrelationStrategy = Field(default=CorrelationStrategy.BY_ACTOR_AND_TARGET, description="关联策略")
    artifact_types: List[str] = Field(default=[], description="用于关联的artifact类型列表，为空时根据strategy自动选择")
    artifact_roles: List[str] = Field(default=[], description="用于关联的artifact角色列表，为空时根据strategy自动选择")
    time_window: str = Field(default="24h", description="时间窗口")
    case_title_template: str = Field(default="", description="Case标题模板，支持{rule_name}, {actor}, {target}等变量")
    include_rule_in_key: bool = Field(default=True, description="是否将规则ID包含在关联key中")


class GroupRule(object):
    VALID_WINDOWS = ['10m', '30m', '1h', '8h', '12h', '24h']

    ROLE_PRIORITY = {
        'Actor': 1,
        'Target': 2,
        'Affected': 3,
        'Related': 4,
        'Unknown': 5,
        'Other': 6
    }

    def __init__(self,
                 config: Optional[CorrelationConfig] = None,
                 rule_id: str = None,
                 correlation_fields: List[str] = None,
                 correlation_window: str = "24h"):

        if config:
            self.rule_id = config.rule_id
            self.strategy = config.strategy
            self.artifact_types = config.artifact_types
            self.artifact_roles = config.artifact_roles
            self.time_window = config.time_window
            self.case_title_template = config.case_title_template
            self.include_rule_in_key = config.include_rule_in_key
        else:
            self.rule_id = rule_id or ""
            self.strategy = CorrelationStrategy.BY_CUSTOM_FIELDS
            self.artifact_types = correlation_fields or []
            self.artifact_roles = []
            self.time_window = correlation_window
            self.case_title_template = ""
            self.include_rule_in_key = True

        if self.time_window not in self.VALID_WINDOWS:
            raise ValueError(f"'{self.time_window}' 不是一个有效的时间窗口选项. 请从 {self.VALID_WINDOWS} 中选择.")

    @staticmethod
    def _get_time_bucket(dt_object: datetime, window: str) -> datetime:
        if window.endswith('m'):
            minutes = int(window[:-1])
            new_minute = (dt_object.minute // minutes) * minutes
            return dt_object.replace(minute=new_minute, second=0, microsecond=0)
        elif window.endswith('h'):
            hours = int(window[:-1])
            if hours == 24:
                return dt_object.replace(hour=0, minute=0, second=0, microsecond=0)
            else:
                new_hour = (dt_object.hour // hours) * hours
                return dt_object.replace(hour=new_hour, minute=0, second=0, microsecond=0)
        return dt_object

    def _extract_artifacts_by_strategy(self, artifacts: List[Any]) -> List[Dict[str, str]]:
        result = []

        role_map = {
            CorrelationStrategy.BY_ACTOR: ['Actor'],
            CorrelationStrategy.BY_TARGET: ['Target'],
            CorrelationStrategy.BY_ACTOR_AND_TARGET: ['Actor', 'Target'],
            CorrelationStrategy.BY_RULE: [],
            CorrelationStrategy.BY_CUSTOM_FIELDS: self.artifact_roles if self.artifact_roles else []
        }

        target_roles = role_map.get(self.strategy, [])

        for artifact in artifacts:
            if hasattr(artifact, 'type') and hasattr(artifact, 'value') and hasattr(artifact, 'role'):
                art_type = str(artifact.type.value) if hasattr(artifact.type, 'value') else str(artifact.type)
                art_value = str(artifact.value) if artifact.value else ""
                art_role = str(artifact.role.value) if hasattr(artifact.role, 'value') else str(artifact.role)
            elif isinstance(artifact, dict):
                art_type = str(artifact.get('type', ''))
                art_value = str(artifact.get('value', ''))
                art_role = str(artifact.get('role', 'Related'))
            else:
                continue

            if self.artifact_types and art_type not in self.artifact_types:
                continue

            if target_roles and art_role not in target_roles:
                continue

            result.append({
                'type': art_type,
                'value': art_value,
                'role': art_role
            })

        result.sort(key=lambda x: (self.ROLE_PRIORITY.get(x['role'], 99), x['type'], x['value']))

        return result

    def generate_correlation_uid(self,
                                 artifacts: List[Any],
                                 timestamp: Optional[Union[int, float, str, datetime]] = None,
                                 rule_id_override: str = None) -> str:

        if timestamp is None:
            processing_dt = datetime.now(timezone.utc)
        elif isinstance(timestamp, datetime):
            processing_dt = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
        elif isinstance(timestamp, str):
            try:
                processing_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                processing_dt = datetime.now(timezone.utc)
        else:
            processing_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)

        time_bucket_dt = self._get_time_bucket(processing_dt, self.time_window)
        time_bucket_str = time_bucket_dt.strftime('%Y%m%d%H%M')

        key_parts = []

        effective_rule_id = rule_id_override or self.rule_id
        if self.include_rule_in_key and effective_rule_id:
            key_parts.append(effective_rule_id)

        key_parts.append(time_bucket_str)

        extracted_artifacts = self._extract_artifacts_by_strategy(artifacts)

        for art in extracted_artifacts:
            key_parts.append(f"{art['role']}:{art['type']}:{art['value']}")

        raw_key = "|".join(key_parts)

        hash_obj = hashlib.sha256(raw_key.encode('utf-8'))
        short_hash = hash_obj.hexdigest()[:16]

        return f"corr-{short_hash}"
