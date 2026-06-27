from rest_framework import serializers

from apps.enrichments.models import Enrichment
from .models import Artifact


class ArtifactSerializer(serializers.ModelSerializer):
    alert_count = serializers.SerializerMethodField()
    enrichment_count = serializers.SerializerMethodField()

    def get_alert_count(self, obj):
        annotated_value = getattr(obj, "alert_count", None)
        if annotated_value is not None:
            return annotated_value
        return obj.alerts.count()

    def get_enrichment_count(self, obj):
        return Enrichment.objects.filter(artifact=obj).count()

    class Meta:
        model = Artifact
        fields = "__all__"
        read_only_fields = ("id", "artifact_id", "created_at", "updated_at")
