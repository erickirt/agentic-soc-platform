import hashlib

from django.db import connection, transaction
from django.utils import timezone

from apps.agentic.models import AgenticJobStatus, CaseAnalysisJob


def _case_analysis_lock_id(case_pk):
    raw_key = str(case_pk)
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=False) & ((1 << 63) - 1)


def _lock_case_analysis(case):
    lock_id = _case_analysis_lock_id(case.pk)
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [lock_id])


@transaction.atomic
def request_case_analysis(*, case, trigger, scheduled_at=None):
    _lock_case_analysis(case)
    existing = (
        CaseAnalysisJob.objects.select_for_update()
        .filter(case=case, status=AgenticJobStatus.PENDING)
        .order_by("scheduled_at", "created_at")
        .first()
    )
    if existing:
        return existing

    return CaseAnalysisJob.objects.create(
        case=case,
        trigger=trigger,
        scheduled_at=scheduled_at or timezone.now(),
    )


@transaction.atomic
def start_case_analysis_job(job):
    locked = CaseAnalysisJob.objects.select_for_update().get(pk=job.pk)
    if locked.status != AgenticJobStatus.PENDING:
        raise ValueError(f"CaseAnalysisJob must be Pending before start, got {locked.status}")
    locked.status = AgenticJobStatus.RUNNING
    locked.started_at = timezone.now()
    locked.error = ""
    locked.save(update_fields=["status", "started_at", "error", "updated_at"])
    return locked


@transaction.atomic
def complete_case_analysis_job(job, *, result_json, case_ai_updates):
    locked = CaseAnalysisJob.objects.select_for_update().select_related("case").get(pk=job.pk)
    if locked.status != AgenticJobStatus.RUNNING:
        raise ValueError(f"CaseAnalysisJob must be Running before complete, got {locked.status}")

    allowed_case_fields = {
        "severity_ai",
        "confidence_ai",
        "impact_ai",
        "priority_ai",
        "verdict_ai",
        "investigation_report_ai_json",
    }
    invalid_fields = set(case_ai_updates) - allowed_case_fields
    if invalid_fields:
        raise ValueError(f"Unsupported case AI update fields: {sorted(invalid_fields)}")

    for field, value in case_ai_updates.items():
        setattr(locked.case, field, value)
    locked.case.full_clean()
    locked.case.save(update_fields=[*case_ai_updates.keys(), "updated_at"])

    locked.status = AgenticJobStatus.SUCCESS
    locked.completed_at = timezone.now()
    locked.result_json = result_json
    locked.error = ""
    locked.save(update_fields=["status", "completed_at", "result_json", "error", "updated_at"])
    return locked


@transaction.atomic
def fail_case_analysis_job(job, error):
    locked = CaseAnalysisJob.objects.select_for_update().get(pk=job.pk)
    if locked.status == AgenticJobStatus.SUCCESS:
        raise ValueError("CaseAnalysisJob cannot be failed after success")
    if locked.status != job.status:
        raise ValueError(f"CaseAnalysisJob status changed from {job.status} to {locked.status}")
    locked.status = AgenticJobStatus.FAILED
    locked.completed_at = timezone.now()
    locked.error = str(error)
    locked.save(update_fields=["status", "completed_at", "error", "updated_at"])
    return locked
