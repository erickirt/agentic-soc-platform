from datetime import date, datetime
from uuid import UUID

from django.contrib.contenttypes.models import ContentType

from apps.agentic.analysis.profiles import AI_PROFILE_INVESTIGATION, get_profile_fields
from apps.audit.models import AuditLog
from apps.comments.models import Comment
from apps.enrichments.models import Enrichment

AUDIT_LOG_LIMIT = 100


def _model_label(obj):
    return obj._meta.label


def _serialize_scalar(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


def _serialize_json_value(value):
    if isinstance(value, dict):
        return {str(key): _serialize_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize_json_value(item) for item in value]
    return _serialize_scalar(value)


def _serialize_user(user):
    if not user:
        return ""
    return user.get_full_name() or user.username


def _serialize_comment(comment):
    return {
        "created_at": _serialize_scalar(comment.created_at),
        "updated_at": _serialize_scalar(comment.updated_at),
        "author": _serialize_user(comment.author),
        "body": comment.body,
    }


def _serialize_audit_log(log):
    return {
        "created_at": _serialize_scalar(log.created_at),
        "action": log.action,
        "actor": _serialize_user(log.actor),
        "changes": _serialize_json_value(log.changes or {}),
        "metadata": _serialize_json_value(log.metadata or {}),
    }


def _enrichments_for(obj):
    model_name = obj._meta.model_name
    if model_name in {"case", "alert", "artifact"}:
        return Enrichment.objects.filter(**{model_name: obj}).order_by("created_at")
    return Enrichment.objects.none()


def _comments_for(obj):
    content_type = ContentType.objects.get_for_model(obj)
    return (
        Comment.objects.filter(content_type=content_type, object_id=obj.pk)
        .select_related("author")
        .order_by("created_at")
    )


def _audit_logs_for(obj):
    content_type = ContentType.objects.get_for_model(obj)
    logs = (
        AuditLog.objects.filter(content_type=content_type, object_id=str(obj.pk))
        .select_related("actor")
        .order_by("-created_at")[:AUDIT_LOG_LIMIT]
    )
    return reversed(list(logs))


def _serialize_relation(obj, field_name, profile):
    if obj._meta.label == "cases.Case" and field_name == "alerts":
        return [serialize_for_ai(alert, profile) for alert in obj.alerts.all().order_by("created_at")]
    if field_name == "artifacts":
        return [serialize_for_ai(artifact, profile) for artifact in obj.artifacts.all().order_by("created_at")]
    if field_name == "enrichments":
        return [serialize_for_ai(enrichment, profile) for enrichment in _enrichments_for(obj)]
    if field_name == "comments":
        return [_serialize_comment(comment) for comment in _comments_for(obj)]
    if obj._meta.label == "cases.Case" and field_name == "audit_logs":
        return [_serialize_audit_log(log) for log in _audit_logs_for(obj)]
    raise AttributeError(f"{obj._meta.label} has no AI relation field {field_name}")


def _serialize_value(obj, field_name, profile):
    if field_name in {"alerts", "artifacts", "enrichments", "comments", "audit_logs"}:
        return _serialize_relation(obj, field_name, profile)
    value = getattr(obj, field_name)
    if field_name == "assignee":
        return _serialize_user(value)
    return _serialize_scalar(value)


def serialize_for_ai(obj, profile):
    fields = get_profile_fields(_model_label(obj), profile)
    return {field_name: _serialize_value(obj, field_name, profile) for field_name in fields}


def serialize_case_for_investigation(case):
    return serialize_for_ai(case, AI_PROFILE_INVESTIGATION)
