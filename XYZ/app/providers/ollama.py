import json
import httpx
from app.models import ToolProposal


def validate_chat_response(data):
    """Validate the native tool-call channel before any proposal can reach the broker."""
    if not isinstance(data, dict) or not isinstance(data.get("message"), dict):
        raise ValueError("Invalid provider response")
    message = data["message"]
    content = message.get("content", "")
    calls = message.get("tool_calls", [])
    if calls is None:
        calls = []
    if message.get("role") != "assistant" or not isinstance(content, str) or len(content) > 32000:
        raise ValueError("Invalid assistant message")
    if not isinstance(calls, list) or len(calls) > 64:
        raise ValueError("Invalid tool-call list")
    normalized = {"role": "assistant", "content": content}
    validated = []
    for call in calls:
        if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
            raise ValueError("Invalid tool call")
        function = call["function"]
        if not isinstance(function.get("name"), str) or not isinstance(function.get("arguments"), dict):
            raise ValueError("Invalid tool-call arguments")
        proposal = ToolProposal(name=function["name"], arguments=function["arguments"])
        validated.append({"function": proposal.model_dump()})
    if validated:
        normalized["tool_calls"] = validated
    if not content.strip() and not validated:
        raise ValueError("Empty assistant response")
    # Reject non-JSON values, non-finite numbers, and oversized structured arguments.
    if len(json.dumps(normalized, ensure_ascii=False, allow_nan=False)) > 64000:
        raise ValueError("Provider message exceeds size limit")
    for field in ("eval_count", "prompt_eval_count"):
        count = data.get(field, 0)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("Invalid token count")
    if data.get("done") is False or data.get("done_reason") == "length":
        raise ValueError("Incomplete provider response")
    return {**data, "message": normalized}


class Ollama:
    def __init__(self, settings, metrics):
        self.settings, self.metrics = settings, metrics

    async def status(self):
        try:
            async with httpx.AsyncClient(timeout=min(self.settings.ollama_timeout, 2), trust_env=False) as client:
                response = await client.get(self.settings.ollama_base_url.rstrip("/") + "/api/tags")
                response.raise_for_status()
                names = [model["name"] for model in response.json().get("models", [])]
            return {"ollama": "CONNECTED", "model": "AVAILABLE" if self.settings.ollama_model in names else "UNAVAILABLE", "models": names}
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return {"ollama": "DISCONNECTED", "model": "UNAVAILABLE", "models": []}

    async def generate(self, prompt, model, max_tokens=512, json_mode=False):
        self.metrics.ollama_calls += 1
        payload = {"model": model, "prompt": prompt, "stream": False,
                   "options": {"temperature": 0, "num_predict": max_tokens}}
        if json_mode:
            payload["format"] = "json"
        async with httpx.AsyncClient(timeout=self.settings.ollama_timeout, trust_env=False) as client:
            response = await client.post(self.settings.ollama_base_url.rstrip("/") + "/api/generate", json=payload)
            response.raise_for_status()
            data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("response"), str) or len(data["response"]) > 32000:
            raise ValueError("Invalid provider response")
        return data

    async def chat(self, messages, model, tool_schemas, max_tokens=512):
        """Use Ollama's native proposal channel; adapters are executed only by Gateway."""
        self.metrics.ollama_calls += 1
        payload = {"model": model, "messages": messages, "stream": False, "think": False,
                   "options": {"temperature": 0, "num_predict": max_tokens}}
        if tool_schemas:
            payload["tools"] = [{"type": "function", "function": {
                "name": name, "parameters": schema,
            }} for name, schema in tool_schemas.items()]
        async with httpx.AsyncClient(timeout=self.settings.ollama_timeout, trust_env=False) as client:
            response = await client.post(self.settings.ollama_base_url.rstrip("/") + "/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
        return validate_chat_response(data)
