"""M2 JavaScript 支援測試：同一條規則（用概念名）跨語言通用。

驗證語言抽象層：規則寫概念名（assignment/call/concat），
引擎依 language 翻成 JS 實際節點名（variable_declarator/call_expression/binary_expression）。
"""
from raven.parser.ast_parser import AstParser, detect_language
from raven.rules.engine import RuleEngine


def _scan_js(source_code: str):
    """用 JS parser + 引擎掃一段 JS，回傳 findings。"""
    engine = RuleEngine.from_directory("raven/rules/definitions/")
    parser = AstParser("javascript")
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return engine.scan(tree.root_node, source, "javascript")


# 語言偵測
def test_detect_language():
    assert detect_language("foo.py") == "python"
    assert detect_language("foo.js") == "javascript"
    assert detect_language("foo.txt") is None


# Hardcoded Secret 規則在 JS 上也能抓（同一條 YAML 規則）
def test_secret_in_javascript():
    findings = [f for f in _scan_js('const API_KEY = "sk-prod-abc123def456";')
                if f.rule_id == "SECRET-001"]
    assert len(findings) == 1


# SQL Injection 規則在 JS 上也能抓
def test_sqli_in_javascript():
    findings = [f for f in _scan_js('db.query("SELECT * WHERE id=" + userInput)')
                if f.rule_id == "SQL-001"]
    assert len(findings) == 1


# JS 安全寫法不誤報
def test_js_no_false_positive():
    findings = _scan_js('const greeting = "hello world";')
    assert len(findings) == 0
