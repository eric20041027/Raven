"""LLM 後端設定：環境變數 + 合理預設，命令列可覆寫。

設定來源優先序（高 → 低）：
    命令列參數  >  環境變數  >  預設值

預設指向 Ollama（跨平台、開源推薦後端）。
api_key 從環境變數讀，避免出現在命令列歷史（安全）。
"""
import os
from dataclasses import dataclass

# 預設後端：Ollama（不需 api_key）
_DEFAULT_BASE_URL = "http://localhost:11434/v1"
_DEFAULT_MODEL = "qwen2.5-coder:7b"


@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    model: str
    api_key: str | None


def load_llm_config(
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> LLMConfig:
    """組出最終 LLM 設定。傳入的參數（來自命令列）優先；否則讀環境變數；再否則用預設。"""
    return LLMConfig(
        base_url=base_url or os.environ.get("RAVEN_LLM_BASE_URL", _DEFAULT_BASE_URL),
        model=model or os.environ.get("RAVEN_LLM_MODEL", _DEFAULT_MODEL),
        # api_key 沒有預設值：Ollama 不需要，oMLX 則須由環境變數提供
        api_key=api_key or os.environ.get("RAVEN_LLM_API_KEY"),
    )
