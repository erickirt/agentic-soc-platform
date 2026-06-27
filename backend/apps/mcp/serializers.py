from django.contrib.contenttypes.models import ContentType

from apps.cases.models import Case
from apps.comments.models import Comment


def _dt(value):
    return value.isoformat() if value else None


def serialize_enrichment(enrichment):
    return {
        "enrichment_id": enrichment.enrichment_id,
        "name": enrichment.name,
        "type": enrichment.type,
        "provider": enrichment.provider,
        "uid": enrichment.uid,
        "value": enrichment.value,
        "desc": enrichment.desc,
        "data": enrichment.data,
        "created_at": _dt(enrichment.created_at),
    }


def serialize_artifact(artifact, *, include_enrichments=True):
    data = {
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "type": artifact.type,
        "role": artifact.role,
        "value": artifact.value,
        "created_at": _dt(artifact.created_at),
    }
    if include_enrichments:
        data["enrichments"] = [serialize_enrichment(item) for item in artifact.enrichments.all()[:20]]
    return data


def serialize_alert(alert, *, include_related=False):
    data = {
        "alert_id": alert.alert_id,
        "case_id": alert.case.case_id if alert.case_id else "",
        "title": alert.title,
        "severity": alert.severity,
        "status": alert.status,
        "confidence": alert.confidence,
        "correlation_uid": alert.correlation_uid,
        "source_uid": alert.source_uid,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "created_at": _dt(alert.created_at),
    }
    if include_related:
        data["artifacts"] = [serialize_artifact(item, include_enrichments=False) for item in alert.artifacts.all()[:50]]
        data["enrichments"] = [serialize_enrichment(item) for item in alert.enrichments.all()[:20]]
    return data


def serialize_comment(comment):
    return {
        "id": comment.id,
        "body": comment.body,
        "author": comment.author.username if comment.author else "",
        "created_at": _dt(comment.created_at),
    }


def serialize_case(case, *, include_related=True):
    data = {
        "case_id": case.case_id,
        "title": case.title,
        "severity": case.severity,
        "confidence": case.confidence,
        "impact": case.impact,
        "priority": case.priority,
        "status": case.status,
        "verdict": case.verdict,
        "severity_ai": case.severity_ai,
        "confidence_ai": case.confidence_ai,
        "impact_ai": case.impact_ai,
        "priority_ai": case.priority_ai,
        "verdict_ai": case.verdict_ai,
        "summary": case.summary,
        "correlation_uid": case.correlation_uid,
        "tags": case.tags,
        "created_at": _dt(case.created_at),
    }
    if include_related:
        content_type = ContentType.objects.get_for_model(Case)
        data["alerts"] = [serialize_alert(alert, include_related=True) for alert in case.alerts.all()[:50]]
        data["enrichments"] = [serialize_enrichment(item) for item in case.enrichments.all()[:20]]
        data["comments"] = [
            serialize_comment(item)
            for item in Comment.objects.filter(content_type=content_type, object_id=str(case.id)).order_by("created_at")[:50]
        ]
        data["playbooks"] = [serialize_playbook(item) for item in case.playbooks.all()[:20]]
    return data


def serialize_playbook(playbook, *, include_related=False):
    data = {
        "playbook_id": playbook.playbook_id,
        "case_id": playbook.case.case_id if playbook.case_id else "",
        "name": playbook.name,
        "user_input": playbook.user_input,
        "job_status": playbook.job_status,
        "job_id": playbook.job_id,
        "remark": playbook.remark,
        "created_at": _dt(playbook.created_at),
    }
    if include_related and playbook.case_id:
        data["case"] = serialize_case(playbook.case, include_related=False)
    return data


def serialize_knowledge(knowledge):
    return {
        "knowledge_id": knowledge.knowledge_id,
        "title": knowledge.title,
        "body": knowledge.body,
        "expires_at": _dt(knowledge.expires_at),
        "source": knowledge.source,
        "tags": knowledge.tags,
        "case_id": knowledge.case.case_id if knowledge.case_id else "",
        "created_at": _dt(knowledge.created_at),
    }
