"""M3 LLM 解釋層測試。

涵蓋兩件事：
  1. 優雅降級契約：有沒有 LLM，掃描結果都完整、不崩
  2. explain 解析邏輯：用 mock 假裝後端回應，測解析（不打真實後端）
"""
import json
from unittest.mock import MagicMock

from raven.rules.engine import Finding
from raven.llm.client import LLMClient, annotate_findings


def _make_finding():
    return Finding(
        rule_id="SECRET-001", severity="HIGH", cwe="CWE-798",
        line=1, snippet='API_KEY = "x"', message="...",
    )


# 無 client（未啟用 LLM）→ findings 原樣回傳，llm_explanation 維持 None
def test_no_client_returns_findings_unchanged():
    findings = [_make_finding()]
    result = annotate_findings(findings, client=None)
    assert len(result) == 1
    assert result[0].llm_explanation is None


# Finding 預設 llm_explanation 為 None（無 LLM 也合法）
def test_finding_defaults_no_explanation():
    assert _make_finding().llm_explanation is None


# explain 正確解析後端回應（用 mock，不打真實後端）
def test_explain_parses_response():
    client = LLMClient(base_url="http://x/v1", model="m")

    # 準備假回應：模型回一段 JSON 字串
    fake_json = json.dumps({"risk_level": "HIGH", "why": "測試風險"})
    # 假裝 response.choices[0].message.content 這條鏈回傳 fake_json
    fake_response = MagicMock()
    fake_response.choices[0].message.content = fake_json
    # 用假物件替換真實的 OpenAI client
    client._client = MagicMock()
    client._client.chat.completions.create.return_value = fake_response

    result = client.explain(_make_finding())
    assert result == {"risk_level": "HIGH", "why": "測試風險"}


# explain 遇到任何錯誤 → 回 None（優雅降級），不崩
def test_explain_graceful_on_error():
    client = LLMClient(base_url="http://x/v1", model="m")
    # 讓 create 一被呼叫就丟例外，模擬連線失敗
    client._client = MagicMock()
    client._client.chat.completions.create.side_effect = Exception("connection refused")

    assert client.explain(_make_finding()) is None   # 降級為 None，不拋例外


# annotate 不可變：不修改原本的 finding 物件
def test_annotate_is_immutable():
    original = _make_finding()
    # 用回 None 的假 client，避免真實網路呼叫（這測試只關心不可變）
    fake_client = MagicMock()
    fake_client.explain.return_value = None
    annotate_findings([original], fake_client)
    assert original.llm_explanation is None   # 原物件未被改動
