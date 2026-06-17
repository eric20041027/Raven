"""LLM 解釋層 —— 可選增強，可缺席。

鐵律：規則引擎是核心、必跑、零依賴；LLM 是可插拔的增強層。
任何 LLM 失敗（無後端、連線錯、JSON 壞）都「優雅降級」為 None，
絕不讓 LLM 問題拖垮整個掃描。

M3：可選的 LLM 增強層。explain 呼叫 OpenAI-compatible 後端，
任何失敗（無後端 / 連線錯 / JSON 壞）都回 None（優雅降級）。
"""
import json
from dataclasses import replace

from openai import OpenAI

from raven.llm.prompts import SYSTEM_PROMPT, build_user_prompt


class LLMClient:
    """呼叫 OpenAI-compatible 後端產生漏洞解釋。

    後端可設定（base_url / api_key / model）——已由 R1 驗證：
    oMLX 需 Authorization: Bearer key、Ollama 不需 key（故 api_key 可選）。
    """

    def __init__(self, base_url: str, model: str, api_key: str | None = None) -> None:
        self.model = model
        # Ollama 不需 key，但 openai SDK 要求非空字串，故給 placeholder
        self._client = OpenAI(base_url=base_url, api_key=api_key or "not-needed")

    def explain(self, finding) -> dict | None:
        """產生單一漏洞的解釋；任何失敗回 None（優雅降級）。"""
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_prompt(finding)},
                ],
                temperature=0.1,                       # 低溫，輸出穩定
                max_tokens=512,
                response_format={"type": "json_object"},  # 強制 JSON
            )
            return json.loads(response.choices[0].message.content)
        except Exception:
            # 優雅降級：無後端 / 連線錯 / JSON 壞 → 不崩，只是沒解釋
            return None


def annotate_findings(findings: list, client: LLMClient | None) -> list:
    """為每個 finding 附加 LLM 解釋（可選步驟）。

    client 為 None（未啟用 --llm / 無後端）→ 原樣回傳 findings，不做任何事。
    這就是「優雅降級」的掛勾點：掃描流程永遠呼叫它，有沒有 LLM 都安全。
    """
    if client is None:
        return findings   # 無 LLM：純規則結果原樣輸出

    annotated = []
    for f in findings:
        explanation = client.explain(f)   # 失敗回 None
        # 不可變更新：產生帶解釋的新 Finding，不修改原物件
        annotated.append(replace(f, llm_explanation=explanation))
    return annotated
