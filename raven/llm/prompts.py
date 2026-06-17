"""LLM prompt 模板：把漏洞組裝成問模型的訊息。

設計要點（對應計劃第 10 節）：
- 強制 JSON 輸出（response_format），減少 parse 失敗
- 低 temperature，輸出穩定
- 限制字數，避免 CLI 顯示爆版
"""

SYSTEM_PROMPT = """你是一位專業的資安審查員，專門分析程式碼中的安全漏洞。
每次回覆必須嚴格按照以下 JSON 格式輸出，不要輸出任何其他內容：

{
  "risk_level": "HIGH | MEDIUM | LOW",
  "why": "一句話說明這段程式碼的具體風險（繁體中文，50 字以內）",
  "attack_scenario": "攻擊者如何利用此漏洞的具體範例（繁體中文，80 字以內）",
  "fixed_code": "修正後的完整程式碼片段"
}"""


def build_user_prompt(finding) -> str:
    """把一個 Finding 組裝成 user prompt。"""
    return f"""以下程式碼被偵測為可能的 {finding.rule_id}（{finding.cwe}）：

第 {finding.line} 行：
{finding.snippet}

規則說明：{finding.message}

請輸出 JSON 分析報告。"""
