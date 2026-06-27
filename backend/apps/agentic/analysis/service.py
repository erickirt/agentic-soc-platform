import json
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone
from langchain_core.messages import HumanMessage, SystemMessage

from apps.agentic.analysis.knowledge import extract_knowledge_keywords, search_knowledge_records
from apps.agentic.analysis.profiles import AI_PROFILE_VERSION
from apps.agentic.analysis.prompts import read_investigation_system_prompt
from apps.agentic.analysis.schemas import AnalysisRecord, InvestigationReport
from apps.agentic.analysis.serializers import serialize_case_for_investigation
from integrations.llm.llmapi import LLMAPI


@dataclass(frozen=True)
class AnalysisResult:
    report: InvestigationReport
    analysis_record: dict


def generate_investigation_report(analysis_input):
    model = LLMAPI().get_model(tag="structured_output").with_structured_output(InvestigationReport)
    return model.invoke(
        [
            SystemMessage(content=read_investigation_system_prompt()),
            HumanMessage(content=json.dumps(analysis_input, ensure_ascii=False)),
        ]
    )


def _source_identity(source):
    if source is None:
        return "", ""
    model_name = source._meta.model_name if hasattr(source, "_meta") else type(source).__name__
    return model_name, str(getattr(source, "pk", ""))


def run_case_analysis(*, case, trigger, user_input="", source=None):
    case_payload = serialize_case_for_investigation(case)
    knowledge_keywords = extract_knowledge_keywords(case_payload)
    knowledge_records = search_knowledge_records(knowledge_keywords)
    analysis_input = {
        "case": case_payload,
        "knowledge": {
            "keywords": knowledge_keywords,
            "records": knowledge_records,
        },
    }
    if user_input:
        analysis_input["user_input"] = user_input

    report = generate_investigation_report(analysis_input)
    source_type, source_id = _source_identity(source)
    record = AnalysisRecord(
        trigger=trigger,
        source_type=source_type,
        source_id=source_id,
        profile_version=AI_PROFILE_VERSION,
        generated_at=timezone.now().isoformat(),
        knowledge_keywords=knowledge_keywords,
        knowledge_records=knowledge_records,
        report=report,
    )

    with transaction.atomic():
        locked_case = case.__class__.objects.select_for_update().get(pk=case.pk)
        locked_case.verdict_ai = report.verdict
        locked_case.severity_ai = report.severity
        locked_case.impact_ai = report.impact
        locked_case.priority_ai = report.priority
        locked_case.confidence_ai = report.confidence
        locked_case.investigation_report_ai_json = record.model_dump_json()
        locked_case.full_clean()
        locked_case.save(
            update_fields=[
                "verdict_ai",
                "severity_ai",
                "impact_ai",
                "priority_ai",
                "confidence_ai",
                "investigation_report_ai_json",
                "updated_at",
            ]
        )
    return AnalysisResult(report=report, analysis_record=record.model_dump())
