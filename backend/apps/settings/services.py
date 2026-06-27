import httpx


def _chat_completions_url(base_url):
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return f"{normalized}/chat/completions"


def _redact(value, secrets):
    redacted = str(value)
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "***")
    return redacted


def test_llm_provider(config):
    api_key = (config.get("api_key") or "").strip()
    base_url = (config.get("base_url") or "").strip()
    model = (config.get("model") or "").strip()
    proxy = (config.get("proxy") or "").strip()

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
        "temperature": 0,
        "max_tokens": 8,
    }
    client_kwargs = {"timeout": 20, "trust_env": False}
    if proxy:
        client_kwargs["proxy"] = proxy

    try:
        with httpx.Client(**client_kwargs) as client:
            response = client.post(_chat_completions_url(base_url), headers=headers, json=payload)
        if response.is_success:
            data = response.json()
            content = ""
            choices = data.get("choices") if isinstance(data, dict) else None
            if choices and isinstance(choices, list):
                message = (choices[0] or {}).get("message") or {}
                content = str(message.get("content") or "")
            return {
                "success": True,
                "detail": "LLM provider responded successfully.",
                "response_preview": content[:200],
            }

        return {
            "success": False,
            "detail": f"LLM provider test failed with HTTP {response.status_code}.",
            "response_preview": _redact(response.text, [api_key])[:500],
        }
    except Exception as exc:
        return {
            "success": False,
            "detail": _redact(exc, [api_key]),
            "response_preview": "",
        }


def test_alienvault_otx_config(config):
    api_key = (config.get("api_key") or "").strip()
    base_url = (config.get("base_url") or "").strip().rstrip("/")
    proxy = (config.get("proxy") or "").strip()
    timeout = float(config.get("timeout_seconds") or 10)

    if not api_key:
        return {
            "success": False,
            "detail": "AlienVault OTX API key is not configured.",
            "response_preview": "",
        }

    client_kwargs = {"timeout": timeout, "trust_env": False}
    if proxy:
        client_kwargs["proxy"] = proxy

    headers = {
        "accept": "application/json",
        "X-OTX-API-KEY": api_key,
    }
    try:
        with httpx.Client(**client_kwargs) as client:
            response = client.get(f"{base_url}/indicators/IPv4/8.8.8.8/general", headers=headers)
        if response.is_success:
            return {
                "success": True,
                "detail": "AlienVault OTX responded successfully.",
                "response_preview": response.text[:500],
            }
        return {
            "success": False,
            "detail": f"AlienVault OTX test failed with HTTP {response.status_code}.",
            "response_preview": _redact(response.text, [api_key])[:500],
        }
    except Exception as exc:
        return {
            "success": False,
            "detail": _redact(exc, [api_key]),
            "response_preview": "",
        }


def test_splunk_config(config):
    import splunklib.client

    password = config.get("password") or ""
    try:
        service = splunklib.client.connect(
            host=config.get("host"),
            port=config.get("port"),
            username=config.get("username"),
            password=password,
            scheme=config.get("scheme") or "https",
            verify=bool(config.get("verify")),
        )
        info = service.info
        return {
            "success": True,
            "detail": "Splunk responded successfully.",
            "response_preview": str({key: info.get(key) for key in ("serverName", "version", "guid")})[:500],
        }
    except Exception as exc:
        return {
            "success": False,
            "detail": _redact(exc, [password]),
            "response_preview": "",
        }


def test_elk_config(config):
    from elasticsearch import Elasticsearch

    api_key = config.get("api_key") or ""
    try:
        client = Elasticsearch(
            (config.get("host") or "").rstrip("/"),
            api_key=api_key,
            verify_certs=bool(config.get("verify_certs")),
            request_timeout=int(config.get("request_timeout_seconds") or 30),
        )
        info = client.info()
        return {
            "success": True,
            "detail": "ELK responded successfully.",
            "response_preview": str({
                "cluster_name": info.get("cluster_name"),
                "version": (info.get("version") or {}).get("number") if isinstance(info.get("version"), dict) else "",
            })[:500],
        }
    except Exception as exc:
        return {
            "success": False,
            "detail": _redact(exc, [api_key]),
            "response_preview": "",
        }
