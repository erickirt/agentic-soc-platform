from django.db.models import Count, Min
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions
from rest_framework.filters import OrderingFilter, SearchFilter

from apps.accounts.permissions import IsBusinessWriterOrReadOnly
from apps.audit.mixins import AuditActorMixin
from apps.common.advanced_filters import AdvancedFilterBackend
from .models import Case
from .serializers import CaseListSerializer, CaseSerializer


class CaseViewSet(AuditActorMixin, viewsets.ModelViewSet):
    queryset = Case.objects.select_related("assignee").annotate(
        alert_count=Count("alerts", distinct=True),
        playbook_count=Count("playbooks", distinct=True),
        first_alert_seen_time=Min("alerts__first_seen_time"),
    ).order_by("-created_at")
    serializer_class = CaseSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]
    lookup_field = "id"
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    search_fields = ("case_id", "title", "description", "summary", "correlation_uid")
    ordering_fields = (
        "created_at",
        "updated_at",
        "acknowledged_time",
        "closed_time",
        "alert_count",
        "playbook_count",
        "severity",
        "severity_ai",
        "priority",
        "priority_ai",
        "status",
        "confidence",
        "confidence_ai",
        "impact",
        "impact_ai",
        "verdict",
        "verdict_ai",
    )
    filterset_fields = (
        "status",
        "severity",
        "priority",
        "category",
        "confidence",
        "impact",
        "verdict",
        "assignee",
    )
    advanced_filter_fields = {
        "case_id": "text",
        "title": "text",
        "status": "select",
        "category": "select",
        "severity": "select",
        "assignee": "user",
        "verdict": "select",
        "priority": "select",
        "confidence": "select",
        "impact": "select",
        "tags": "tag",
        "acknowledged_time": "date",
        "closed_time": "date",
        "created_at": "date",
        "updated_at": "date",
        "description": "text",
        "summary": "text",
        "correlation_uid": "text",
    }

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.action == "list":
            return queryset.defer("investigation_report_ai_json")
        return queryset

    def get_serializer_class(self):
        if self.action == "list":
            return CaseListSerializer
        return CaseSerializer
