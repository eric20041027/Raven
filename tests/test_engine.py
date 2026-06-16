"""M2 引擎測試（TDD：先寫這個讓它紅，再寫引擎讓它綠）。

驗證標準沿用 M1：引擎用 YAML 規則跑出的結果，要跟 M1 寫死版一致。
"""
from raven.parser.ast_parser import AstParser
from raven.rules.engine import RuleEngine


def _scan_with_engine(source_code: str):
    """用 YAML 引擎掃一段程式碼，回傳 findings。"""
    engine = RuleEngine.from_directory("raven/rules/definitions/")
    parser = AstParser()
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return engine.scan(tree.root_node, source)


# ── 引擎能載入 YAML 規則 ──────────────────────────────
def test_engine_loads_rules():
    engine = RuleEngine.from_directory("raven/rules/definitions/")
    assert len(engine.rules) >= 1          # 至少載到 1 條規則
    assert engine.rules[0].id == "SECRET-001"


# ── 引擎跑出跟 M1 一樣的結果：正例該抓到 ──────────────
def test_engine_detects_secret():
    findings = _scan_with_engine('API_KEY = "sk-prod-abc123def456ghi789"')
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].rule_id == "SECRET-001"


# ── 反例：os.environ 不該誤報（結構條件 right_type=string）──
def test_engine_ignores_env_var():
    findings = _scan_with_engine('SAFE_KEY = os.environ["API_KEY"]')
    assert len(findings) == 0


# ── 反例：普通短字串不該誤報 ──────────────────────────
def test_engine_ignores_plain_string():
    findings = _scan_with_engine('greeting = "hello world"')
    assert len(findings) == 0
