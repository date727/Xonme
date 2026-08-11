"""Server-only configuration for report-generation models and providers."""

import os
from dataclasses import dataclass

from fastapi import HTTPException


@dataclass(frozen=True)
class ModelConfig:
    key: str
    display_name: str
    provider: str
    model: str
    base_url: str
    api_key: str
    request_options: dict


DEFAULT_MODEL_KEY = os.getenv("DEFAULT_MODEL_ID", "deepseek-v4-flash")


def get_model_config(model_key: str | None) -> ModelConfig:
    """Return one allow-listed model config without exposing secrets to clients."""
    siliconflow_base = os.getenv("SILICONFLOW_BASE_URL", "").rstrip("/")
    siliconflow_key = os.getenv("SILICONFLOW_API_KEY", "")
    openai_base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    openai_key = os.getenv("OPENAI_API_KEY", "")
    models = {
        "deepseek-v4-flash": ModelConfig(
            "deepseek-v4-flash", "DeepSeek V4 Flash", "SiliconFlow",
            "deepseek-ai/DeepSeek-V4-Flash", siliconflow_base, siliconflow_key,
            {
                "enable_thinking": True,
                "reasoning_effort": "high",
                "temperature": 0.7,
                "top_p": 0.7,
                "top_k": 50,
            },
        ),
        "qwen-3-6": ModelConfig(
            "qwen-3-6", "Qwen 3.6", "SiliconFlow",
            "Qwen/Qwen3.6-35B-A3B", siliconflow_base, siliconflow_key,
            {
                "enable_thinking": True,
                "temperature": 1.0,
                "top_p": 0.95,
                "top_k": 20,
                "min_p": 0.0,
                "presence_penalty": 1.5,
            },
        ),
        "glm-5-2": ModelConfig(
            "glm-5-2", "GLM 5.2", "SiliconFlow",
            "zai-org/GLM-5.2", siliconflow_base, siliconflow_key,
            {
                "enable_thinking": True,
                "thinking_budget": 4096,
                "temperature": 1.0,
                "top_p": 0.95,
            },
        ),
        "gpt-5-5": ModelConfig(
            "gpt-5-5", "GPT-5.5", "OpenAI",
            "gpt-5.5", openai_base, openai_key,
            {"reasoning": {"effort": "medium"}},
        ),
    }
    config = models.get(model_key or DEFAULT_MODEL_KEY)
    if not config:
        raise HTTPException(status_code=400, detail="Unsupported report model")
    if not config.base_url or not config.api_key:
        raise HTTPException(status_code=500, detail=f"Model is not configured: {config.display_name}")
    return config


def get_chat_completions_url(config: ModelConfig) -> str:
    base_url = config.base_url.rstrip("/")
    if config.provider == "SiliconFlow" and not base_url.endswith("/v1"):
        base_url = f"{base_url}/v1"
    return f"{base_url}/chat/completions"


def public_model_options() -> list[dict[str, str]]:
    return [
        {"id": "deepseek-v4-flash", "label": "DeepSeek V4 Flash"},
        {"id": "qwen-3-6", "label": "Qwen 3.6"},
        {"id": "glm-5-2", "label": "GLM 5.2"},
        {"id": "gpt-5-5", "label": "GPT-5.5"},
    ]
