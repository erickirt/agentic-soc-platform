from django.db.models import Count
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets, permissions
from rest_framework.filters import OrderingFilter, SearchFilter

from apps.accounts.permissions import IsBusinessWriterOrReadOnly
from apps.audit.mixins import AuditActorMixin
from apps.common.advanced_filters import AdvancedFilterBackend
from .models import Artifact
from .serializers import ArtifactSerializer


class ArtifactViewSet(AuditActorMixin, viewsets.ModelViewSet):
    queryset = Artifact.objects.annotate(alert_count=Count("alerts", distinct=True)).order_by("-created_at")
    serializer_class = ArtifactSerializer
    permission_classes = [permissions.IsAuthenticated, IsBusinessWriterOrReadOnly]
    lookup_field = "id"
    filter_backends = (DjangoFilterBackend, SearchFilter, OrderingFilter, AdvancedFilterBackend)
    search_fields = ("artifact_id", "value", "name", "type", "role")
    ordering_fields = ("created_at", "updated_at", "type", "role", "alert_count")
    filterset_fields = ("type", "role", "alerts__id")
    advanced_filter_fields = {
        "artifact_id": "text",
        "type": "select",
        "role": "select",
        "name": "text",
        "value": "text",
        "created_at": "date",
        "updated_at": "date",
    }

    def get_queryset(self):
        queryset = super().get_queryset()
        alert_id = self.request.query_params.get("alerts")
        if alert_id:
            queryset = queryset.filter(alerts__id=alert_id)
        return queryset
