from apps.mcp.auth import ApiKeyMCPMiddleware
from apps.mcp.server import create_mcp_server

mcp_server = create_mcp_server()
mcp_asgi_app = ApiKeyMCPMiddleware(mcp_server.streamable_http_app())
