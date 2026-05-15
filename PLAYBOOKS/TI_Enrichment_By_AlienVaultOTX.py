import json

from Lib.api import is_ipaddress
from Lib.baseplaybook import BasePlaybook
from PLUGINS.AlienVaultOTX.alienvaultotx import AlienVaultOTX
from PLUGINS.SIRP.sirpapi import Artifact, Case
from PLUGINS.SIRP.sirpcoremodel import EnrichmentModel, ArtifactModel, ArtifactType, EnrichmentType, EnrichmentProvider
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus, PlaybookModel


TI_ENRICHMENT_TYPE = EnrichmentType.THREAT_INTELLIGENCE
TI_PROVIDER = EnrichmentProvider.ALIENVAULT_OTX


def _query_ip(value: str) -> dict:
    if not is_ipaddress(value):
        return {"error": "Invalid IP address format."}
    return AlienVaultOTX.query_ip(value)


def _query_hash(value: str) -> dict:
    return AlienVaultOTX.query_file(value)


def _query_url(value: str) -> dict:
    return AlienVaultOTX.query_url(value)


OTX_QUERY_HANDLERS = {
    ArtifactType.IP_ADDRESS: _query_ip,
    ArtifactType.HASH: _query_hash,
    ArtifactType.URL_STRING: _query_url,
    ArtifactType.UNIFORM_RESOURCE_LOCATOR: _query_url,
}


class Playbook(BasePlaybook):
    NAME = "TI Enrichment By AlienVaultOTX"
    DESC = "TI Enrichment By AlienVaultOTX"

    def __init__(self):
        super().__init__()  # do not delete this code

    @staticmethod
    def _normalize_artifact_type(artifact_type):
        if isinstance(artifact_type, ArtifactType):
            return artifact_type
        try:
            return ArtifactType(artifact_type)
        except ValueError:
            return artifact_type

    def _query_ti(self, artifact) -> dict:
        artifact_type = self._normalize_artifact_type(artifact.type)
        handler = OTX_QUERY_HANDLERS.get(artifact_type)
        if not handler:
            return {
                "error": "Unsupported type.",
                "artifact_type": str(artifact.type),
                "supported_types": [artifact_type.value for artifact_type in OTX_QUERY_HANDLERS],
            }
        return handler(artifact.value or "")

    @staticmethod
    def _update_artifact_enrichment(artifact, ti_result: dict):
        enrichments = artifact.enrichments or []
        for enrichment in enrichments:
            if enrichment.type == TI_ENRICHMENT_TYPE and enrichment.provider == TI_PROVIDER:
                enrichment.data = json.dumps(ti_result)
                break
        else:
            enrichment = EnrichmentModel(
                name="TI Enrichment",
                type=TI_ENRICHMENT_TYPE,
                provider=TI_PROVIDER,
                value=artifact.value,
                data=json.dumps(ti_result),
            )
            enrichments.append(enrichment)
        model_tmp = ArtifactModel(row_id=artifact.row_id, enrichments=enrichments)
        Artifact.update(model_tmp)

    @staticmethod
    def _collect_unique_artifacts(case):
        artifacts = {}
        artifact_refs = 0
        for alert in case.alerts or []:
            for artifact in alert.artifacts or []:
                artifact_refs += 1
                if artifact and artifact.row_id and artifact.row_id not in artifacts:
                    artifacts[artifact.row_id] = artifact
        return artifact_refs, artifacts

    def run(self):
        try:
            case_row_id = self.param_source_row_id
            case = Case.get(case_row_id, lazy_load=False)
            if not case:
                message = f"Case not found. row_id: {case_row_id}"
                self.logger.error(message)
                self.update_playbook_status(PlaybookJobStatus.FAILED, message)
                return

            artifact_refs, artifacts = self._collect_unique_artifacts(case)
            stats = {
                "alerts": len(case.alerts or []),
                "artifacts": artifact_refs,
                "unique": len(artifacts),
                "enriched": 0,
                "unsupported": 0,
                "invalid": 0,
                "errors": 0,
            }

            for artifact in artifacts.values():
                try:
                    self.logger.info(f"Querying threat intelligence for artifact: {artifact}")
                    ti_result = self._query_ti(artifact)
                    if ti_result.get("error") == "Unsupported type.":
                        stats["unsupported"] += 1
                    elif ti_result.get("error") == "Invalid IP address format.":
                        stats["invalid"] += 1
                    self._update_artifact_enrichment(artifact, ti_result)
                    stats["enriched"] += 1
                except Exception as e:
                    stats["errors"] += 1
                    self.logger.exception(
                        f"Error during TI enrichment for artifact row_id={artifact.row_id}, "
                        f"type={artifact.type}, value={artifact.value}: {e}"
                    )

            message = (
                "Threat intelligence enrichment completed. "
                f"alerts={stats['alerts']}, artifacts={stats['artifacts']}, unique={stats['unique']}, "
                f"enriched={stats['enriched']}, unsupported={stats['unsupported']}, "
                f"invalid={stats['invalid']}, errors={stats['errors']}"
            )
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, message)
        except Exception as e:
            self.logger.exception(e)
            self.update_playbook_status(PlaybookJobStatus.FAILED, f"Error during TI enrichment: {e}")
        return


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    model = PlaybookModel(source_row_id='3a22cbbf-5b33-4727-aa99-0ab8f763c196')
    module = Playbook()
    module._playbook_model = model

    module.run()
