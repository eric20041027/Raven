"""M3 LLM 解釋層測試 —— 第一刀：優雅降級契約。

核心鐵律：有沒有 LLM，掃描結果都完整、不崩。
"""
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


# client.explain 目前回 None（骨架）→ annotate 後仍 None，但不崩
def test_client_explain_graceful_none():
    client = LLMClient(base_url="http://localhost:11434/v1", model="qwen2.5-coder:7b")
    findings = [_make_finding()]
    result = annotate_findings(findings, client)
    assert len(result) == 1
    assert result[0].llm_explanation is None   # 優雅降級：失敗不崩，只是沒解釋


# annotate 不可變：不修改原本的 finding 物件
def test_annotate_is_immutable():
    original = _make_finding()
    annotate_findings([original], LLMClient("http://x/v1", "m"))
    assert original.llm_explanation is None   # 原物件未被改動
