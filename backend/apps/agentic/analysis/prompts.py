from pathlib import Path

from django.conf import settings

from apps.settings.runtime_config import get_prompt_language

ANALYSIS_SYSTEM_PROMPT_PATH = ("investigation", "System")
KNOWLEDGE_KEYWORD_PROMPT_PATH = ("investigation", "KnowledgeKeywords")
KNOWLEDGE_EXTRACTION_PROMPT_PATH = ("knowledge_extraction", "System")


def read_prompt_file(directory, prompt_name):
    filename = f"{prompt_name}_{get_prompt_language()}.md"
    return (Path(settings.BASE_DIR) / "data" / "playbooks" / directory / filename).read_text(encoding="utf-8")


def read_investigation_system_prompt():
    return read_prompt_file(*ANALYSIS_SYSTEM_PROMPT_PATH)


def read_investigation_knowledge_keyword_prompt():
    return read_prompt_file(*KNOWLEDGE_KEYWORD_PROMPT_PATH)


def read_knowledge_extraction_prompt():
    return read_prompt_file(*KNOWLEDGE_EXTRACTION_PROMPT_PATH)
