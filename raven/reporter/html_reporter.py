"""HTML 報告：把掃描結果渲染成一份自包含、離線可開、可互動的 report.html。

設計重點：
  * 重用 json_reporter.build_report 整理資料（DRY），這裡只負責渲染。
  * 純 Python 手拼字串，零模板引擎依賴。
  * Pygments 伺服端高亮：上色寫死進 HTML，離線打開也有顏色（不靠 CDN）。
  * CSS / JS 全內嵌：單一檔案、不依賴網路。
  * 前端 JS 即時過濾：報告含全部漏洞，瀏覽器端按嚴重度切換顯示。
"""
import html as html_lib

from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name, guess_lexer

from raven.reporter.json_reporter import build_report

# 嚴重度對應的標籤顏色（CSS 用）。
_SEVERITY_COLORS = {
    "HIGH": "#e5484d",
    "MEDIUM": "#f5a623",
    "LOW": "#4cc38a",
}


def print_report(scan_path, file_count: int, rule_count: int, findings: list) -> str:
    """組出 HTML 報告字串。

    注意：HTML 不適合直接印到終端機，故回傳字串由呼叫端決定怎麼存。
    （簽名對齊其他 reporter 的 print_report，方便 main.py 統一分派。）
    """
    report = build_report(scan_path, file_count, rule_count, findings)
    return build_html(report)


def build_html(report: dict) -> str:
    """把 report dict 渲染成一份完整的自包含 HTML 文件。"""
    meta = report["scan_meta"]
    summary = report["summary"]
    findings = report["findings"]

    target = html_lib.escape(str(meta["target"]))
    pygments_css = HtmlFormatter().get_style_defs(".highlight")

    findings_html = (
        "\n".join(_render_finding(f) for f in findings)
        if findings
        else '<p class="empty">🎉 沒有發現任何漏洞。</p>'
    )

    return _PAGE_TEMPLATE.format(
        target=target,
        files_scanned=meta["files_scanned"],
        rules_applied=meta["rules_applied"],
        total=summary["total"],
        high=summary.get("HIGH", 0),
        medium=summary.get("MEDIUM", 0),
        low=summary.get("LOW", 0),
        filter_buttons=_render_filter_buttons(),
        findings=findings_html,
        pygments_css=pygments_css,
        severity_css=_render_severity_css(),
    )


def _render_finding(f: dict) -> str:
    """渲染單一漏洞卡片。所有使用者/原始碼內容都經跳脫或 Pygments 安全處理。"""
    severity = f["severity"]
    highlighted = _highlight_code(f["snippet"], f["file"])

    explanation = ""
    if f.get("llm_explanation"):
        explanation = (
            f'<div class="explanation">🤖 {html_lib.escape(f["llm_explanation"])}</div>'
        )

    return _FINDING_TEMPLATE.format(
        severity=severity,
        severity_label=html_lib.escape(severity),
        rule_id=html_lib.escape(f["rule_id"]),
        cwe=html_lib.escape(f["cwe"]),
        file=html_lib.escape(str(f["file"])),
        line=f["line"],
        message=html_lib.escape(f["message"]),
        code=highlighted,
        explanation=explanation,
    )


def _highlight_code(snippet: str, filename: str) -> str:
    """用 Pygments 把程式碼片段上色成 HTML。

    Pygments 的 HtmlFormatter 會自行跳脫程式碼內容，所以這裡的輸出對
    含特殊字元的 snippet 是安全的（不會被當 HTML 注入）。
    """
    try:
        lexer = get_lexer_by_name(_lexer_name_for(filename))
    except Exception:
        # 認不出語言就用猜的；再不行退回純文字（仍會跳脫）。
        try:
            lexer = guess_lexer(snippet)
        except Exception:
            return f"<pre class=\"highlight\">{html_lib.escape(snippet)}</pre>"
    return highlight(snippet, lexer, HtmlFormatter())


def _lexer_name_for(filename: str) -> str:
    """依副檔名挑 Pygments lexer 名。"""
    if filename.endswith(".js"):
        return "javascript"
    return "python"


def _render_filter_buttons() -> str:
    """嚴重度篩選按鈕（前端 JS 即時 toggle）。"""
    buttons = ['<button class="filter-btn active" data-filter="ALL">全部</button>']
    for sev in ("HIGH", "MEDIUM", "LOW"):
        buttons.append(f'<button class="filter-btn" data-filter="{sev}">{sev}</button>')
    return "\n".join(buttons)


def _render_severity_css() -> str:
    """每個嚴重度的標籤顏色 CSS。"""
    return "\n".join(
        f".badge-{sev} {{ background: {color}; }}"
        for sev, color in _SEVERITY_COLORS.items()
    )


# 單一漏洞卡片。data-severity 供前端 JS 篩選。
_FINDING_TEMPLATE = """\
<div class="finding" data-severity="{severity}">
  <div class="finding-head">
    <span class="badge badge-{severity}">{severity_label}</span>
    <span class="rule-id">{rule_id}</span>
    <span class="cwe">{cwe}</span>
  </div>
  <div class="location">{file}:{line}</div>
  <div class="message">{message}</div>
  <div class="code">{code}</div>
  {explanation}
</div>"""


# 整頁模板。CSS / JS 全內嵌，無外部依賴。
_PAGE_TEMPLATE = """\
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RAVEN 掃描報告</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", sans-serif; margin: 0;
          background: #0d1117; color: #e6edf3; }}
  header {{ padding: 24px 32px; border-bottom: 1px solid #30363d; }}
  h1 {{ margin: 0 0 8px; font-size: 22px; }}
  .target {{ color: #8b949e; word-break: break-all; }}
  .summary {{ display: flex; gap: 16px; margin-top: 16px; flex-wrap: wrap; }}
  .summary div {{ background: #161b22; padding: 8px 16px; border-radius: 8px;
                  border: 1px solid #30363d; }}
  main {{ padding: 24px 32px; }}
  .filters {{ margin-bottom: 20px; display: flex; gap: 8px; }}
  .filter-btn {{ background: #161b22; color: #e6edf3; border: 1px solid #30363d;
                 padding: 6px 16px; border-radius: 6px; cursor: pointer; }}
  .filter-btn.active {{ background: #238636; border-color: #238636; }}
  .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
              padding: 16px; margin-bottom: 16px; }}
  .finding-head {{ display: flex; gap: 10px; align-items: center; margin-bottom: 8px; }}
  .badge {{ color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 12px;
            font-weight: 600; }}
  {severity_css}
  .rule-id {{ font-weight: 600; }}
  .cwe {{ color: #8b949e; font-size: 13px; }}
  .location {{ color: #8b949e; font-size: 13px; margin-bottom: 6px; }}
  .message {{ margin-bottom: 10px; }}
  .code pre {{ margin: 0; padding: 12px; border-radius: 6px; overflow-x: auto; }}
  .explanation {{ margin-top: 10px; padding: 10px; background: #0d1117;
                  border-left: 3px solid #58a6ff; border-radius: 4px;
                  font-size: 14px; }}
  .empty {{ color: #8b949e; font-size: 16px; }}
  .hidden {{ display: none; }}
  {pygments_css}
</style>
</head>
<body>
<header>
  <h1>🪶 RAVEN 掃描報告</h1>
  <div class="target">{target}</div>
  <div class="summary">
    <div>掃描檔案：<b>{files_scanned}</b></div>
    <div>套用規則：<b>{rules_applied}</b></div>
    <div>漏洞總數：<b>{total}</b></div>
    <div>HIGH：<b>{high}</b></div>
    <div>MEDIUM：<b>{medium}</b></div>
    <div>LOW：<b>{low}</b></div>
  </div>
</header>
<main>
  <div class="filters">
    {filter_buttons}
  </div>
  <div id="findings">
    {findings}
  </div>
</main>
<script>
  // 前端嚴重度即時過濾：點按鈕 toggle 對應 .finding 的顯示。
  const buttons = document.querySelectorAll('.filter-btn');
  const findings = document.querySelectorAll('.finding');
  buttons.forEach(function (btn) {{
    btn.addEventListener('click', function () {{
      buttons.forEach(function (b) {{ b.classList.remove('active'); }});
      btn.classList.add('active');
      const filter = btn.getAttribute('data-filter');
      findings.forEach(function (f) {{
        const match = filter === 'ALL' || f.getAttribute('data-severity') === filter;
        f.classList.toggle('hidden', !match);
      }});
    }});
  }});
</script>
</body>
</html>"""
