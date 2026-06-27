from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase, override_settings

from apps.agentic.analysis.prompts import (
    read_investigation_system_prompt,
    read_knowledge_extraction_prompt,
    read_investigation_knowledge_keyword_prompt,
)


class PromptLoaderTests(SimpleTestCase):
    def test_reads_expected_prompt_files_for_configured_language(self):
        with TemporaryDirectory() as temp_dir:
            base_dir = Path(temp_dir)
            investigation_dir = base_dir / "data" / "playbooks" / "investigation"
            extraction_dir = base_dir / "data" / "playbooks" / "knowledge_extraction"
            investigation_dir.mkdir(parents=True)
            extraction_dir.mkdir(parents=True)

            (investigation_dir / "System_en.md").write_text("investigation prompt en", encoding="utf-8")
            (investigation_dir / "KnowledgeKeywords_en.md").write_text("keyword prompt en", encoding="utf-8")
            (extraction_dir / "System_en.md").write_text("knowledge extraction prompt en", encoding="utf-8")
            (investigation_dir / "System_zh.md").write_text("investigation prompt zh", encoding="utf-8")
            (investigation_dir / "KnowledgeKeywords_zh.md").write_text("keyword prompt zh", encoding="utf-8")
            (extraction_dir / "System_zh.md").write_text("knowledge extraction prompt zh", encoding="utf-8")

            with override_settings(BASE_DIR=base_dir, AGENTIC_PROMPT_LANGUAGE="en"):
                self.assertEqual(read_investigation_system_prompt(), "investigation prompt en")
                self.assertEqual(read_investigation_knowledge_keyword_prompt(), "keyword prompt en")
                self.assertEqual(read_knowledge_extraction_prompt(), "knowledge extraction prompt en")

            with override_settings(BASE_DIR=base_dir, AGENTIC_PROMPT_LANGUAGE="zh"):
                self.assertEqual(read_investigation_system_prompt(), "investigation prompt zh")
                self.assertEqual(read_investigation_knowledge_keyword_prompt(), "keyword prompt zh")
                self.assertEqual(read_knowledge_extraction_prompt(), "knowledge extraction prompt zh")
