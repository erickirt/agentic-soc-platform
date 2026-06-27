from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    LLMProviderConfigViewSet,
    AgenticRuntimeConfigView,
    AgenticRuntimeCustomDefinitionsRefreshView,
    LdapConfigView,
    LdapTestView,
    SiemElkConfigView,
    SiemElkTestView,
    SiemSplunkConfigView,
    SiemSplunkTestView,
    ThreatIntelAlienVaultOTXConfigView,
    ThreatIntelAlienVaultOTXTestView,
)


router = DefaultRouter()
router.register("llm-providers", LLMProviderConfigViewSet, basename="llm-provider")

urlpatterns = [
    path("settings/threat-intel/otx/", ThreatIntelAlienVaultOTXConfigView.as_view(), name="threat-intel-otx-config"),
    path("settings/threat-intel/otx/test/", ThreatIntelAlienVaultOTXTestView.as_view(), name="threat-intel-otx-test"),
    path("settings/siem/splunk/", SiemSplunkConfigView.as_view(), name="siem-splunk-config"),
    path("settings/siem/splunk/test/", SiemSplunkTestView.as_view(), name="siem-splunk-test"),
    path("settings/siem/elk/", SiemElkConfigView.as_view(), name="siem-elk-config"),
    path("settings/siem/elk/test/", SiemElkTestView.as_view(), name="siem-elk-test"),
    path("settings/ldap/", LdapConfigView.as_view(), name="ldap-config"),
    path("settings/ldap/test/", LdapTestView.as_view(), name="ldap-test"),
    path("settings/agentic-runtime/", AgenticRuntimeConfigView.as_view(), name="agentic-runtime-config"),
    path("settings/agentic-runtime/custom-definitions/refresh/", AgenticRuntimeCustomDefinitionsRefreshView.as_view(), name="agentic-runtime-custom-definitions-refresh"),
    path("settings/", include(router.urls)),
]
