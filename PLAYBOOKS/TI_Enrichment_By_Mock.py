import json

from Lib.baseplaybook import BasePlaybook
from PLUGINS.SIRP.sirpapi import Artifact, Case
from PLUGINS.SIRP.sirpcoremodel import EnrichmentModel, ArtifactModel, ArtifactType, EnrichmentType, EnrichmentProvider
from PLUGINS.SIRP.sirpextramodel import PlaybookJobStatus, PlaybookModel

TI_ENRICHMENT_TYPE = EnrichmentType.THREAT_INTELLIGENCE
TI_PROVIDER = EnrichmentProvider.MOCK_TI_PROVIDER


def _mock_ip_result(value: str) -> dict:
    return {
        "malicious": True,
        "score": 85,
        "indicator_type": "ip",
        "indicator": value,
        "description": "This IP is associated with known malicious activities.",
        "source": "MockTIProvider",
        "last_seen": "2024-10-01T12:34:56Z",
    }


def _mock_hash_result(value: str) -> dict:
    return {
        "malicious": True,
        "score": 90,
        "indicator_type": "file",
        "indicator": value,
        "description": "This file hash is associated with known malware samples.",
        "source": "MockTIProvider",
        "last_seen": "2024-10-01T12:34:56Z",
    }


def _mock_url_result(value: str) -> dict:
    return {
        "malicious": True,
        "score": 80,
        "indicator_type": "url",
        "indicator": value,
        "description": "This URL is associated with suspicious or malicious activity.",
        "source": "MockTIProvider",
        "last_seen": "2024-10-01T12:34:56Z",
    }


MOCK_QUERY_HANDLERS = {
    ArtifactType.IP_ADDRESS: _mock_ip_result,
    ArtifactType.HASH: _mock_hash_result,
    ArtifactType.URL_STRING: _mock_url_result,
    ArtifactType.UNIFORM_RESOURCE_LOCATOR: _mock_url_result,
}


class Playbook(BasePlaybook):
    NAME = "TI Enrichment (Mock)"
    DESC = "Simulate threat intelligence enrichment. This playbook is for testing and demonstration purposes only. It does not perform real threat intelligence queries."

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
        handler = MOCK_QUERY_HANDLERS.get(artifact_type)
        if not handler:
            return {
                "error": "Unsupported type.",
                "artifact_type": str(artifact.type),
                "supported_types": [artifact_type.value for artifact_type in MOCK_QUERY_HANDLERS],
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
                name="Mock TI Enrichment",
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
                "errors": 0,
            }

            for artifact in artifacts.values():
                try:
                    self.logger.info(f"Mock threat intelligence enrichment for artifact: {artifact}")
                    ti_result = self._query_ti(artifact)
                    if ti_result.get("error") == "Unsupported type.":
                        stats["unsupported"] += 1
                    self._update_artifact_enrichment(artifact, ti_result)
                    stats["enriched"] += 1
                except Exception as e:
                    stats["errors"] += 1
                    self.logger.exception(
                        f"Error during mock TI enrichment for artifact row_id={artifact.row_id}, "
                        f"type={artifact.type}, value={artifact.value}: {e}"
                    )

            message = (
                "Mock threat intelligence enrichment completed. "
                f"alerts={stats['alerts']}, artifacts={stats['artifacts']}, unique={stats['unique']}, "
                f"enriched={stats['enriched']}, unsupported={stats['unsupported']}, errors={stats['errors']}"
            )
            self.update_playbook_status(PlaybookJobStatus.SUCCESS, message)
        except Exception as e:
            self.logger.exception(e)
            self.update_playbook_status(PlaybookJobStatus.FAILED, f"Error during mock TI enrichment: {e}")
        return


if __name__ == "__main__":
    import os
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ASP.settings")
    django.setup()
    model = PlaybookModel(source_row_id='44958bcb-31ab-4fdf-85e7-60e02f9677f2')
    module = Playbook()
    module._playbook_model = model
    module.run()
