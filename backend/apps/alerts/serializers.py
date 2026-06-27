from rest_framework import serializers
from rest_framework.permissions import SAFE_METHODS

from apps.enrichments.models import Enrichment
from .models import Alert


class AlertSerializer(serializers.ModelSerializer):
    artifact_count = serializers.SerializerMethodField()
    enrichment_count = serializers.SerializerMethodField()
    case_id = serializers.CharField(source="case.id", read_only=True)
    case_readable_id = serializers.CharField(source="case.case_id", read_only=True)
    case_title = serializers.CharField(source="case.title", read_only=True)
    case_status = serializers.CharField(source="case.status", read_only=True)
    case_category = serializers.CharField(source="case.category", read_only=True)

    def get_artifact_count(self, obj):
        request = self.context.get("request")
        if request is not None and request.method not in SAFE_METHODS:
            return obj.artifacts.count()

        prefetched_artifacts = getattr(obj, "_prefetched_objects_cache", {}).get("artifacts")
        if prefetched_artifacts is not None:
            return len(prefetched_artifacts)

        annotated_value = getattr(obj, "artifact_count", None)
        if annotated_value is not None:
            return annotated_value

        return obj.artifacts.count()

    def get_enrichment_count(self, obj):
        return Enrichment.objects.filter(alert=obj).count()

    class Meta:
        model = Alert
        fields = "__all__"
        read_only_fields = ("id", "alert_id", "created_at", "updated_at")
