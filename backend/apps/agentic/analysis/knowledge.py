import json

from django.db.models import Q
from django.utils import timezone
from langchain_core.messages import HumanMessage, SystemMessage

from apps.agentic.analysis.profiles import AI_PROFILE_MCP
from apps.agentic.analysis.prompts import read_investigation_knowledge_keyword_prompt
from apps.agentic.analysis.schemas import KnowledgeSearchKeywords
from apps.agentic.analysis.serializers import serialize_for_ai
from apps.knowledge.models import Knowledge
from integrations.llm.llmapi import LLMAPI

MAX_KNOWLEDGE_KEYWORDS = 8
MAX_KNOWLEDGE_RECORDS = 10


def normalize_knowledge_keywords(keywords):
    normalized = []
    seen = set()
    for keyword in keywords or []:
        if not isinstance(keyword, str):
            continue
        value = " ".join(keyword.strip().split())
        if not value:
            continue
        value = value[:80]
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(value)
        if len(normalized) >= MAX_KNOWLEDGE_KEYWORDS:
            break
    return normalized


def fallback_knowledge_keywords(case_payload):
    keywords = [case_payload.get("title", "")]
    keywords.extend(case_payload.get("tags", []) or [])
    for alert in case_payload.get("alerts", []) or []:
        keywords.append(alert.get("rule_name", ""))
        keywords.append(alert.get("title", ""))
        for artifact in alert.get("artifacts", []) or []:
            keywords.append(artifact.get("value", ""))
    return normalize_knowledge_keywords(keywords)


def extract_knowledge_keywords(case_payload):
    system_prompt = read_investigation_knowledge_keyword_prompt()
    try:
        model = LLMAPI().get_model(tag="structured_output").with_structured_output(KnowledgeSearchKeywords)
        result = model.invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=json.dumps(case_payload, ensure_ascii=False)),
            ]
        )
        return normalize_knowledge_keywords(result.keywords)
    except Exception:
        return fallback_knowledge_keywords(case_payload)


def search_knowledge_records(keywords, limit=MAX_KNOWLEDGE_RECORDS):
    keywords = normalize_knowledge_keywords(keywords)
    if not keywords:
        return []

    keyword_query = Q()
    for keyword in keywords:
        keyword_query |= Q(title__icontains=keyword)
        keyword_query |= Q(body__icontains=keyword)
        keyword_query |= Q(tags__contains=[keyword])

    valid_time_query = Q(expires_at__isnull=True) | Q(expires_at__gte=timezone.now())
    queryset = Knowledge.objects.filter(valid_time_query).filter(keyword_query).order_by("-created_at")[:limit]
    return [serialize_for_ai(record, AI_PROFILE_MCP) for record in queryset]
