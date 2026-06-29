"""
ASGI config for asp project.
"""

import contextlib
import os

from django.core.asgi import get_asgi_application
from starlette.applications import Starlette
from starlette.routing import Mount
from channels.routing import ProtocolTypeRouter, URLRouter

from apps.common.logging import configure_process_file_logging

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "asp.settings")

django_application = get_asgi_application()
configure_process_file_logging("asgi")

from apps.mcp.asgi import mcp_asgi_app, mcp_server  # noqa: E402
from apps.realtime.auth import JWTAuthMiddleware  # noqa: E402
from apps.realtime.routing import websocket_urlpatterns  # noqa: E402


@contextlib.asynccontextmanager
async def lifespan(app):
    async with mcp_server.session_manager.run():
        yield


http_application = Starlette(
    routes=[
        Mount("/api/mcp", app=mcp_asgi_app),
        Mount("/", app=django_application),
    ],
    lifespan=lifespan,
)

application = ProtocolTypeRouter({
    "http": http_application,
    "lifespan": http_application,
    "websocket": JWTAuthMiddleware(URLRouter(websocket_urlpatterns)),
})
