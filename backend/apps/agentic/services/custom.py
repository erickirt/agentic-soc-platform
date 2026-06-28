from pathlib import Path

from django.conf import settings

from apps.agentic.runtime.module import scan_module_definitions
from apps.agentic.services.playbooks import scan_playbook_definitions
from integrations.siem.registry import reload_registry, scan_registry_configs

PROMPT_LANGUAGES = ("en", "zh")


def _source_for_path(path):
    custom_dir = Path(settings.CUSTOM_DIR).resolve()
    resolved_path = Path(path).resolve()
    try:
        resolved_path.relative_to(custom_dir)
    except ValueError:
        return "official"
    return "custom"


def _module_record(definition):
    return {
        "name": definition.name,
        "stream_name": definition.stream_name,
        "thread_num": definition.thread_num,
        "path": str(definition.path),
        "source": _source_for_path(definition.path),
    }


def _playbook_record(definition):
    raw_tags = getattr(definition.script_class, "TAGS", []) or []
    tags = [raw_tags] if isinstance(raw_tags, str) else list(raw_tags)
    return {
        "name": definition.name,
        "description": getattr(definition.script_class, "DESC", ""),
        "tags": tags,
        "path": str(definition.path),
        "source": _source_for_path(definition.path),
    }


def _siem_record(item):
    path = item["path"]
    return {
        **item,
        "source": _source_for_path(path),
    }


def _prompt_record(definition, prompt_name, language, path):
    return {
        "playbook": definition.name,
        "prompt": prompt_name,
        "language": language,
        "path": str(path),
        "source": "custom",
    }


def _scan_playbook_prompts(playbooks):
    items = []
    errors = []
    for definition in playbooks:
        if _source_for_path(definition.path) != "custom":
            continue
        required_prompts = getattr(definition.script_class, "REQUIRED_PROMPTS", []) or []
        for prompt_name in required_prompts:
            for language in PROMPT_LANGUAGES:
                path = definition.script_class.prompt_path(prompt_name, language=language)
                if path.exists():
                    items.append(_prompt_record(definition, prompt_name, language, path))
                else:
                    errors.append({
                        "path": str(path),
                        "error": f"Missing custom playbook prompt: {definition.name} {prompt_name}_{language}",
                    })
    return items, errors


def refresh_custom_definitions():
    reload_registry()
    modules, module_errors = scan_module_definitions()
    playbooks, playbook_errors = scan_playbook_definitions()
    siem_indices, siem_errors = scan_registry_configs()
    prompt_items, prompt_errors = _scan_playbook_prompts(playbooks)
    sections = {
        "modules": {
            "items": [_module_record(item) for item in modules],
            "errors": module_errors,
        },
        "playbooks": {
            "items": [_playbook_record(item) for item in playbooks],
            "errors": playbook_errors,
        },
        "siem": {
            "items": [_siem_record(item) for item in siem_indices],
            "errors": siem_errors,
        },
        "prompts": {
            "items": prompt_items,
            "errors": prompt_errors,
        },
    }
    result = dict(sections)
    result["success"] = not any(section["errors"] for section in sections.values())
    result["counts"] = {
        "modules": len(result["modules"]["items"]),
        "playbooks": len(result["playbooks"]["items"]),
        "siem": len(result["siem"]["items"]),
        "prompts": len(result["prompts"]["items"]),
        "errors": sum(len(section["errors"]) for section in sections.values()),
    }
    return result
