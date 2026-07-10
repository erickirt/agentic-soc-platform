from django.db.models import Count
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions
from rest_framework.filters import OrderingFilter, SearchFilter

from apps.accounts.permissions import IsBusinessWriterOrReadOnly
from apps.audit.mixins import AuditActorMixin
from apps.common.advanced_filters import AdvancedFilterBackend
from .models import Alert
from .serializers import AlertSerializer


class AlertViewSet(AuditActorMixin, viewsets.ModelViewSet):
    queryset = Alert.objects.select_related("case").prefetch_related("artifacts").order_by("-created_at")
    serializer_class = AlertSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]
    lookup_field = "id"
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    search_fields = (
        "alert_id",
        "title",
        "desc",
        "rule_id",
        "rule_name",
        "correlation_uid",
        "source_uid",
        "product_vendor",
        "product_name",
        "product_feature",
        "tactic",
        "technique",
        "status_detail",
        "remediation",
    )
    ordering_fields = (
        "created_at",
        "updated_at",
        "artifact_count",
        "severity",
        "confidence",
        "impact",
        "status",
        "disposition",
        "action",
        "risk_level",
        "first_seen_time",
        "last_seen_time",
    )
    filterset_fields = (
        "status",
        "severity",
        "confidence",
        "impact",
        "disposition",
        "action",
        "product_category",
        "risk_level",
        "case__id",
        "artifacts__id",
    )
    advanced_filter_fields = {
        "alert_id": "text",
        "title": "text",
        "severity": "select",
        "confidence": "select",
        "impact": "select",
        "status": "select",
        "disposition": "select",
        "action": "select",
        "risk_level": "select",
        "product_category": "select",
        "product_vendor": "text",
        "product_name": "text",
        "rule_id": "text",
        "rule_name": "text",
        "correlation_uid": "text",
        "source_uid": "text",
        "labels": "tag",
        "first_seen_time": "date",
        "last_seen_time": "date",
        "created_at": "date",
    }

    def is_ordering_by_artifact_count(self):
        raw_ordering = self.request.query_params.get("ordering", "")
        return any(field.strip().lstrip("-") == "artifact_count" for field in raw_ordering.split(","))

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.is_ordering_by_artifact_count():
            queryset = queryset.annotate(artifact_count=Count("artifacts", distinct=True))
        artifact_id = self.request.query_params.get("artifacts")
        if artifact_id:
            queryset = queryset.filter(artifacts__id=artifact_id)
        return queryset
