"""M2 Command Injection 規則測試（TDD：先紅，再寫 YAML 規則讓它綠）。"""
from raven.parser.ast_parser import AstParser
from raven.rules.engine import RuleEngine


def _scan(source_code: str):
    engine = RuleEngine.from_directory("raven/rules/definitions/")
    parser = AstParser()
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return engine.scan(tree.root_node, source)


def _cmd_findings(source_code: str):
    """只取 CMD-001 的命中。"""
    return [f for f in _scan(source_code) if f.rule_id == "CMD-001"]


# ── 正例：os.system 拼接使用者輸入該抓到 ──────────────
def test_detects_command_injection():
    code = 'os.system("rm -rf " + user_input)'
    findings = _cmd_findings(code)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


# ── 反例：固定字串無拼接不該誤報 ──────────────────────
def test_ignores_static_command():
    code = 'os.system("ls -la")'
    findings = _cmd_findings(code)
    assert len(findings) == 0
