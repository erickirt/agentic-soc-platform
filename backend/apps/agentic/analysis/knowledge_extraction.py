import json
from dataclasses import dataclass

from django.db import transaction
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from apps.agentic.analysis.prompts import read_knowledge_extraction_prompt
from apps.agentic.analysis.serializers import serialize_case_for_investigation
from apps.knowledge.models import Knowledge, KnowledgeSource
from integrations.llm.llmapi import LLMAPI


class KnowledgeExtractionLLMResult(BaseModel):
    has_knowledge: bool
    title: str | None = None
    body: str | None = None
    tags: list[str] = Field(default_factory=list)
    reason: str


@dataclass(frozen=True)
class KnowledgeExtractionResult:
    has_knowledge: bool
    remark: str
    knowledge: Knowledge | None = None
    reason: str = ""


def normalize_knowledge_tags(tags):
    normalized = []
    seen = set()
    for tag in tags or []:
        if not isinstance(tag, str):
            continue
        value = tag.strip()
        if not value:
            continue
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(value)
        if len(normalized) >= 10:
            break
    return normalized


def generate_knowledge_extraction(case_payload, *, user_input=""):
    model = LLMAPI().get_model(tag="structured_output").with_structured_output(KnowledgeExtractionLLMResult)
    payload = {"case": case_payload}
    if user_input:
        payload["user_input"] = user_input
    return model.invoke(
        [
            SystemMessage(content=read_knowledge_extraction_prompt()),
            HumanMessage(content=json.dumps(payload, ensure_ascii=False)),
        ]
    )


@transaction.atomic
def extract_knowledge_from_case(*, case, user_input="", source=None):
    locked_case = case.__class__.objects.select_for_update().get(pk=case.pk)
    if not locked_case.verdict:
        return KnowledgeExtractionResult(
            has_knowledge=False,
            remark="Case has no analyst verdict, skipping knowledge extraction.",
            reason="Case has no analyst verdict.",
        )

    case_payload = serialize_case_for_investigation(locked_case)
    extraction = generate_knowledge_extraction(case_payload, user_input=user_input)
    existing = Knowledge.objects.select_for_update().filter(case=locked_case).first()

    if not extraction.has_knowledge:
        if existing:
            existing.delete()
        return KnowledgeExtractionResult(
            has_knowledge=False,
            remark=f"No knowledge extracted: {extraction.reason}",
            reason=extraction.reason,
        )

    title = (extraction.title or "").strip()
    body = (extraction.body or "").strip()
    if not title or not body:
        raise ValueError("Knowledge extraction returned has_knowledge=true without title and body.")

    tags = normalize_knowledge_tags(extraction.tags)
    if existing is None:
        knowledge = Knowledge(case=locked_case)
    else:
        knowledge = existing
    knowledge.title = title
    knowledge.body = body
    knowledge.source = KnowledgeSource.CASE
    knowledge.tags = tags
    knowledge.full_clean()
    knowledge.save()
    return KnowledgeExtractionResult(
        has_knowledge=True,
        remark=f"Knowledge created: {title}. Reason: {extraction.reason}",
        knowledge=knowledge,
        reason=extraction.reason,
    )
