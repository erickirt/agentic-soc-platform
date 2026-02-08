import json
from typing import Annotated, Literal

# change this to your actual threat intelligence api
from PLUGINS.Mock.TI import TI


class AgentThreatIntelligence(object):

    @staticmethod
    def threat_intelligence_lookup(
            ioc_type: Annotated[Literal["ip", "domain", "hash", "url"], "The type of IOC. Supported: 'ip', 'domain', 'hash', 'url'"],
            ioc_value: Annotated[str, "The value of the IOC (e.g., '1.1.1.1' or 'a1b2...')"],
    ) -> Annotated[str, "Threat intelligence report including risk score and categories"]:
        """
        Check Threat Intelligence reputation for an artifact.
        """
        report = TI.lookup(ioc_type, ioc_value)
        return json.dumps(report)
