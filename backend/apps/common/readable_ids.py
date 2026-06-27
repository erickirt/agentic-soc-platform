from django.db import IntegrityError, transaction


READABLE_ID_WIDTH = 6
READABLE_ID_RETRIES = 3


def format_readable_id(prefix: str, number: int) -> str:
    return f"{prefix}_{number:0{READABLE_ID_WIDTH}d}"


def parse_readable_id_number(value: str | None, prefix: str) -> int:
    if not value:
        return 0
    marker = f"{prefix}_"
    if not value.startswith(marker):
        return 0
    suffix = value[len(marker):]
    return int(suffix) if suffix.isdigit() else 0


def next_readable_id(model_class, field_name: str, prefix: str) -> str:
    values = model_class.objects.exclude(**{field_name: ""}).values_list(field_name, flat=True)
    max_number = 0
    for value in values:
        max_number = max(max_number, parse_readable_id_number(value, prefix))
    return format_readable_id(prefix, max_number + 1)


def assign_readable_id(instance, field_name: str, prefix: str) -> None:
    if getattr(instance, field_name):
        return
    setattr(instance, field_name, next_readable_id(type(instance), field_name, prefix))


def save_with_readable_id(instance, field_name: str, prefix: str, *args, **kwargs):
    for attempt in range(READABLE_ID_RETRIES):
        assign_readable_id(instance, field_name, prefix)
        try:
            with transaction.atomic():
                return super(type(instance), instance).save(*args, **kwargs)
        except IntegrityError:
            if attempt == READABLE_ID_RETRIES - 1:
                raise
            setattr(instance, field_name, "")
    return super(type(instance), instance).save(*args, **kwargs)
