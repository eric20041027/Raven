"""三個 SQL 引擎（pattern / 單函式 taint / inter-procedural）的合併去重測試。

同一行的 SQL 漏洞只留最強者，優先級：
    inter-procedural (SQL-TAINT-IP-001) > 單函式 taint (SQL-TAINT-001)
    > pattern (SQL-001)
非 SQL 規則（Secret/cmd/eval）不受影響。
"""
from raven.main import _merge_findings
from raven.rules.engine import Finding
from raven.rules.taint import TaintFinding


def _pattern_sql(line):
    return Finding(rule_id="SQL-001", severity="HIGH", cwe="CWE-89",
                   line=line, snippet="x", message="pattern")


def _intra_sql(line):
    return TaintFinding(rule_id="SQL-TAINT-001", severity="HIGH", cwe="CWE-89",
                        line=line, snippet="x", message="intra")


def _ip_sql(line):
    return TaintFinding(rule_id="SQL-TAINT-IP-001", severity="HIGH", cwe="CWE-89",
                        line=line, snippet="x", message="ip")


def _other(rule_id, line):
    return Finding(rule_id=rule_id, severity="MEDIUM", cwe="CWE-X",
                   line=line, snippet="x", message="other")


def _ids(findings):
    return sorted(f.rule_id for f in findings)


# ── 同一行三引擎都報 → 只留 IP（最強）──
def test_all_three_on_same_line_keeps_ip():
    merged = _merge_findings(
        pattern_findings=[_pattern_sql(5)],
        taint_findings=[_intra_sql(5)],
        ip_findings=[_ip_sql(5)],
        decided_lines={5},
    )
    assert _ids(merged) == ["SQL-TAINT-IP-001"]


# ── 同一行 pattern + intra → 留 intra ──
def test_pattern_and_intra_keeps_intra():
    merged = _merge_findings(
        pattern_findings=[_pattern_sql(3)],
        taint_findings=[_intra_sql(3)],
        ip_findings=[],
        decided_lines={3},
    )
    assert _ids(merged) == ["SQL-TAINT-001"]


# ── 不同行各報 → 都保留 ──
def test_different_lines_all_kept():
    merged = _merge_findings(
        pattern_findings=[_pattern_sql(1)],
        taint_findings=[_intra_sql(2)],
        ip_findings=[_ip_sql(3)],
        decided_lines={2},
    )
    assert _ids(merged) == ["SQL-001", "SQL-TAINT-001", "SQL-TAINT-IP-001"]


# ── 非 SQL 規則不受影響 ──
def test_non_sql_rules_untouched():
    merged = _merge_findings(
        pattern_findings=[_other("SECRET-001", 5), _other("CMD-001", 5)],
        taint_findings=[],
        ip_findings=[_ip_sql(5)],
        decided_lines=set(),
    )
    # 同行的 Secret / cmd 不該被 SQL 的去重影響
    assert _ids(merged) == ["CMD-001", "SECRET-001", "SQL-TAINT-IP-001"]


# ── IP 跨函式：源頭行的 pattern SQL 也該讓位 ──
def test_ip_suppresses_pattern_on_same_line():
    merged = _merge_findings(
        pattern_findings=[_pattern_sql(8)],
        taint_findings=[],
        ip_findings=[_ip_sql(8)],
        decided_lines=set(),
    )
    assert _ids(merged) == ["SQL-TAINT-IP-001"]
