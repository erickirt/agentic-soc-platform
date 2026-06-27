from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldDoesNotExist
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import viewsets, permissions
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from .helpers import readable_label
from .models import AuditLog


def foreign_key_field(model, field_name):
    try:
        field = model._meta.get_field(field_name)
    except FieldDoesNotExist:
        return None
    if getattr(field, "many_to_one", False) and getattr(field, "remote_field", None):
        return field
    return None


def related_labels(field, values):
    related_model = field.remote_field.model
    if not isinstance(related_model, type):
        return {}
    lookup_values = [value for value in values if value not in (None, "")]
    if not lookup_values:
        return {}
    return {
        str(obj.pk): readable_label(obj)
        for obj in related_model._default_manager.filter(pk__in=lookup_values)
    }


def display_changes(log):
    changes = log.changes or {}
    model = log.content_type.model_class()
    if not model or not isinstance(changes, dict):
        return changes

    display = {}
    for field_name, raw_change in changes.items():
        if not isinstance(raw_change, dict):
            display[field_name] = raw_change
            continue

        field = foreign_key_field(model, field_name)
        if not field:
            display[field_name] = raw_change
            continue

        labels = related_labels(
            field,
            [raw_change[key] for key in ("from", "to") if key in raw_change],
        )
        display_change = dict(raw_change)
        for key in ("from", "to"):
            if key in display_change:
                display_change[key] = labels.get(str(display_change[key]), display_change[key])
        display[field_name] = display_change
    return display


def datetime_param(params, name):
    raw_value = params.get(name)
    if not raw_value:
        return None
    value = parse_datetime(raw_value)
    if value is None:
        raise ValidationError({name: "Invalid datetime."})
    if timezone.is_naive(value):
        return timezone.make_aware(value)
    return value


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = AuditLog.objects.select_related("actor", "content_type")
        params = self.request.query_params
        ct = params.get("content_type")
        oid = params.get("object_id")
        if ct and oid:
            try:
                ct_model = ContentType.objects.get(model=ct)
                qs = qs.filter(content_type=ct_model, object_id=oid)
            except ContentType.DoesNotExist:
                qs = qs.none()

        action = params.get("action")
        if action:
            qs = qs.filter(action=action)

        actor = params.get("actor")
        if actor == "system":
            qs = qs.filter(actor__isnull=True)
        elif actor:
            qs = qs.filter(actor_id=actor)

        field = params.get("field")
        if field:
            qs = qs.filter(Q(changes__has_key=field) | Q(metadata__relation=field))

        created_after = datetime_param(params, "created_after")
        if created_after:
            qs = qs.filter(created_at__gte=created_after)

        created_before = datetime_param(params, "created_before")
        if created_before:
            qs = qs.filter(created_at__lte=created_before)

        return qs

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        data = [
            {
                "id": log.id,
                "action": log.action,
                "actor": log.actor.username if log.actor else None,
                "actor_id": log.actor_id,
                "actor_name": log.actor.get_full_name() if log.actor else "",
                "changes": log.changes,
                "display_changes": display_changes(log),
                "metadata": log.metadata,
                "created_at": log.created_at,
            }
            for log in queryset[:100]
        ]
        return Response(data)
