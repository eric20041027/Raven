"""M2 Unsafe eval/exec 規則測試（TDD：先紅，再寫 YAML 規則讓它綠）。"""
from raven.parser.ast_parser import AstParser
from raven.rules.engine import RuleEngine


def _scan(source_code: str):
    engine = RuleEngine.from_directory("raven/rules/definitions/")
    parser = AstParser()
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return engine.scan(tree.root_node, source)


def _eval_findings(source_code: str):
    """只取 EVAL-001 的命中。"""
    return [f for f in _scan(source_code) if f.rule_id == "EVAL-001"]


# 正例：呼叫 eval 即警告（不需拼接）
def test_detects_eval():
    findings = _eval_findings("result = eval(user_input)")
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


# 正例：exec 同樣命中
def test_detects_exec():
    findings = _eval_findings("exec(user_input)")
    assert len(findings) == 1


# 反例：普通函式呼叫不該誤報
def test_ignores_normal_call():
    findings = _eval_findings("print(message)")
    assert len(findings) == 0
