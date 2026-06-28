from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    LLMProviderConfigViewSet,
    LdapConfigView,
    LdapTestView,
    RuntimeConfigView,
    RuntimeCustomDefinitionsRefreshView,
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
    path("settings/runtime/", RuntimeConfigView.as_view(), name="runtime-config"),
    path("settings/runtime/custom-definitions/refresh/", RuntimeCustomDefinitionsRefreshView.as_view(), name="runtime-custom-definitions-refresh"),
    path("settings/", include(router.urls)),
]
