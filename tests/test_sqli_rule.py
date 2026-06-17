"""M2 SQL Injection 規則測試（TDD：先紅，再擴充引擎支援 call 類規則）。"""
from raven.parser.ast_parser import AstParser
from raven.rules.engine import RuleEngine


def _scan(source_code: str):
    engine = RuleEngine.from_directory("raven/rules/definitions/")
    parser = AstParser()
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return engine.scan(tree.root_node, source)


def _sqli_findings(source_code: str):
    """只取 SQL-001 的命中（過濾掉其他規則）。"""
    return [f for f in _scan(source_code) if f.rule_id == "SQL-001"]


# ── 正例：字串拼接進 execute 該抓到 ──────────────────
def test_detects_sql_injection():
    code = 'cursor.execute("SELECT * FROM users WHERE id=" + user_input)'
    findings = _sqli_findings(code)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


# ── 反例：參數化查詢不該誤報 ──────────────────────────
def test_ignores_parameterized_query():
    code = 'cursor.execute("SELECT * FROM users WHERE id=?", (user_input,))'
    findings = _sqli_findings(code)
    assert len(findings) == 0


# ── 反例：非資料庫函式的拼接不該誤報 ──────────────────
def test_ignores_non_db_call():
    code = 'print("hello " + name)'
    findings = _sqli_findings(code)
    assert len(findings) == 0
