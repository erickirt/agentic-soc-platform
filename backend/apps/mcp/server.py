from django.conf import settings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import TransportSecuritySettings

from apps.mcp.tools import REGISTERED_MCP_TOOLS


def _transport_security_settings():
    allowed_hosts = set(settings.ALLOWED_HOSTS or [])
    if "*" in allowed_hosts:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)

    expanded_hosts = {"127.0.0.1:*", "localhost:*", "[::1]:*"}
    for host in allowed_hosts:
        if not host:
            continue
        expanded_hosts.add(host)
        if ":" not in host:
            expanded_hosts.add(f"{host}:*")
    return TransportSecuritySettings(allowed_hosts=sorted(expanded_hosts))


def create_mcp_server(server_factory=FastMCP):
    mcp = server_factory(
        "ASP-MCP",
        stateless_http=True,
        json_response=True,
        streamable_http_path="/",
        transport_security=_transport_security_settings(),
    )
    for tool in REGISTERED_MCP_TOOLS:
        mcp.add_tool(tool)
    return mcp
