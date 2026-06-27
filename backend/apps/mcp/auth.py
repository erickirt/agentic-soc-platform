import json

from asgiref.sync import sync_to_async
from django.utils import timezone

from apps.accounts.models import UserApiKey


class ApiKeyMCPMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        header = _authorization_header(scope)
        ok, message, user, api_key = await sync_to_async(_authenticate_header)(header)
        if not ok:
            return await _send_json(send, 401, {"detail": message})

        scope["user"] = user
        scope["api_key"] = api_key
        return await self.app(scope, receive, send)


def _authorization_header(scope):
    for key, value in scope.get("headers", []):
        if key.lower() == b"authorization":
            return value.decode("utf-8", errors="ignore")
    return ""


def _authenticate_header(header):
    if not header:
        return False, "API key required", None, None
    parts = header.split()
    if len(parts) != 2 or parts[0] != "Api-Key":
        return False, "Invalid API key header", None, None
    try:
        api_key = UserApiKey.objects.select_related("user").get(key=parts[1])
    except UserApiKey.DoesNotExist:
        return False, "Invalid API key", None, None
    if api_key.is_expired:
        return False, "API key expired", None, None
    if not api_key.user.is_active:
        return False, "API key user disabled", None, None
    api_key.last_used_at = timezone.now()
    api_key.save(update_fields=["last_used_at", "updated_at"])
    return True, "", api_key.user, api_key


async def _send_json(send, status, payload):
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": body})
