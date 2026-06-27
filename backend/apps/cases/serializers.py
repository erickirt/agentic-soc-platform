from django.utils import timezone
from rest_framework import serializers

from apps.alerts.serializers import AlertSerializer
from apps.enrichments.models import Enrichment
from apps.inbox.notifications import notify_case_assignment
from .models import Case, CaseStatus


class CaseSerializer(serializers.ModelSerializer):
    alerts = AlertSerializer(many=True, read_only=True)
    alert_count = serializers.IntegerField(read_only=True, default=0)
    playbook_count = serializers.IntegerField(read_only=True, default=0)
    enrichment_count = serializers.SerializerMethodField()
    assignee_name = serializers.SerializerMethodField()
    first_alert_seen_time = serializers.SerializerMethodField()
    detection_time_seconds = serializers.SerializerMethodField()
    acknowledgement_time_seconds = serializers.SerializerMethodField()
    response_time_seconds = serializers.SerializerMethodField()

    def _get_user_name(self, user):
        if not user:
            return ""
        return user.get_full_name() or user.username

    def get_assignee_name(self, obj):
        return self._get_user_name(obj.assignee)

    def get_enrichment_count(self, obj):
        return Enrichment.objects.filter(case=obj).count()

    def _duration_seconds(self, start, end):
        if not start or not end:
            return None
        return int((end - start).total_seconds())

    def _first_alert_seen_time(self, obj):
        annotated_value = getattr(obj, "first_alert_seen_time", None)
        if annotated_value is not None:
            return annotated_value
        return obj.alerts.filter(first_seen_time__isnull=False).order_by("first_seen_time").values_list("first_seen_time", flat=True).first()

    def get_first_alert_seen_time(self, obj):
        value = self._first_alert_seen_time(obj)
        if value is None:
            return None
        return serializers.DateTimeField().to_representation(value)

    def get_detection_time_seconds(self, obj):
        return self._duration_seconds(self._first_alert_seen_time(obj), obj.created_at)

    def get_acknowledgement_time_seconds(self, obj):
        return self._duration_seconds(obj.created_at, obj.acknowledged_time)

    def get_response_time_seconds(self, obj):
        return self._duration_seconds(obj.acknowledged_time, obj.closed_time)

    def update(self, instance, validated_data):
        previous_assignee_id = instance.assignee_id
        previous_status = instance.status or ""
        next_status = validated_data.get("status", previous_status) or ""
        status_changed = next_status != previous_status
        now = timezone.now()

        if (
            status_changed
            and previous_status in ("", CaseStatus.NEW)
            and next_status != CaseStatus.NEW
            and not instance.acknowledged_time
            and "acknowledged_time" not in validated_data
        ):
            validated_data["acknowledged_time"] = now

        if (
            status_changed
            and next_status == CaseStatus.CLOSED
            and not instance.closed_time
            and "closed_time" not in validated_data
        ):
            validated_data["closed_time"] = now

        updated = super().update(instance, validated_data)
        request = self.context.get("request")
        actor = getattr(request, "user", None) if request else None
        notify_case_assignment(updated, previous_assignee_id=previous_assignee_id, actor=actor)
        return updated

    class Meta:
        model = Case
        fields = "__all__"
        read_only_fields = ("id", "case_id", "created_at", "updated_at")


class CaseListSerializer(CaseSerializer):
    class Meta(CaseSerializer.Meta):
        exclude = ("investigation_report_ai_json",)
        fields = None
