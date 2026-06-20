"""M5：HTML 報告（--format html）的測試。

html_reporter 重用 json_reporter.build_report 整理資料，只負責渲染成
一個自包含的 HTML 字串（CSS/JS 內嵌、Pygments 高亮寫死，離線可開）。

測 build_html 純函式：給一個 report dict，回一段 HTML 字串。
"""
from raven.reporter import html_reporter


def _sample_report():
    """一份含 2 個漏洞的報告 dict（對齊 json_reporter.build_report 的輸出）。"""
    return {
        "scan_meta": {
            "target": "https://github.com/user/repo.git",
            "files_scanned": 3,
            "rules_applied": 5,
        },
        "findings": [
            {
                "file": "app.py",
                "rule_id": "SQL-001",
                "severity": "HIGH",
                "cwe": "CWE-89",
                "line": 4,
                "snippet": 'cursor.execute("SELECT * FROM t WHERE id=" + uid)',
                "message": "SQL injection",
                "llm_explanation": None,
            },
            {
                "file": "util.js",
                "rule_id": "SECRET-001",
                "severity": "MEDIUM",
                "cwe": "CWE-798",
                "line": 12,
                "snippet": 'const key = "sk-abc123"',
                "message": "Hardcoded secret",
                "llm_explanation": "這是一個寫死的金鑰。",
            },
        ],
        "summary": {"total": 2, "HIGH": 1, "MEDIUM": 1, "LOW": 0},
    }


def test_build_html_returns_full_document():
    """產出一份完整 HTML 文件。"""
    html = html_reporter.build_html(_sample_report())
    assert html.lstrip().lower().startswith("<!doctype html")
    assert "</html>" in html


def test_build_html_is_self_contained():
    """自包含：CSS 與 JS 內嵌，不靠外部 CDN（離線可開）。"""
    html = html_reporter.build_html(_sample_report())
    assert "<style" in html
    assert "<script" in html
    # 不應該有外部 CDN 連結（highlight.js 等）
    assert "http://" not in html and "https://cdn" not in html.replace(
        "https://github.com/user/repo.git", ""  # target 本身的 URL 不算
    )


def test_build_html_shows_meta_and_summary():
    """標題顯示掃描目標與摘要數字。"""
    html = html_reporter.build_html(_sample_report())
    assert "https://github.com/user/repo.git" in html
    assert "SQL-001" in html
    assert "SECRET-001" in html


def test_build_html_renders_each_finding():
    """每個漏洞都被渲染（含檔名、行號、訊息）。"""
    html = html_reporter.build_html(_sample_report())
    assert "app.py" in html
    assert "util.js" in html
    assert "SQL injection" in html
    assert "Hardcoded secret" in html


def test_build_html_includes_severity_filter_controls():
    """含前端嚴重度篩選的控制項（按鈕 + data 屬性供 JS 篩選）。"""
    html = html_reporter.build_html(_sample_report())
    # 每個 finding 帶 severity 標記，供 JS 篩選
    assert 'data-severity="HIGH"' in html
    assert 'data-severity="MEDIUM"' in html
    # 有篩選用的互動元素
    assert "filter" in html.lower()


def test_build_html_escapes_user_content():
    """漏洞內容含 HTML 特殊字元時要跳脫，避免報告本身被注入。"""
    report = _sample_report()
    report["findings"][0]["snippet"] = '<img src=x onerror="alert(1)">'
    report["findings"][0]["message"] = "<script>bad</script>"
    html = html_reporter.build_html(report)
    # 原始的危險標籤不該以可執行形式出現
    assert "<img src=x onerror=" not in html
    assert "<script>bad</script>" not in html
    # 跳脫後的形式應該在
    assert "&lt;img" in html or "&lt;script&gt;bad" in html


def test_build_html_handles_zero_findings():
    """沒有漏洞時也要產出合法 HTML（不爆）。"""
    report = {
        "scan_meta": {"target": "clean/", "files_scanned": 1, "rules_applied": 5},
        "findings": [],
        "summary": {"total": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }
    html = html_reporter.build_html(report)
    assert "</html>" in html
    assert "0" in html  # total 0
