"""M5 JSON reporter 測試：確認輸出結構正確、可被 parse。"""
import json

from raven.rules.engine import Finding
from raven.reporter.json_reporter import build_report


def _finding():
    return Finding(
        rule_id="SQL-001", severity="HIGH", cwe="CWE-89",
        line=4, snippet='execute("..." + x)', message="...",
    )


# 報告結構：含 scan_meta / findings / summary
def test_report_structure():
    report = build_report("foo/", 1, 4, [("foo/a.py", _finding())])
    assert report["scan_meta"]["files_scanned"] == 1
    assert report["scan_meta"]["rules_applied"] == 4
    assert len(report["findings"]) == 1
    assert report["summary"]["total"] == 1
    assert report["summary"]["HIGH"] == 1


# finding 轉 dict：欄位齊全、file 是字串
def test_finding_to_dict_fields():
    report = build_report("foo/", 1, 4, [("foo/a.py", _finding())])
    f = report["findings"][0]
    assert f["file"] == "foo/a.py"
    assert f["rule_id"] == "SQL-001"
    assert f["line"] == 4
    assert f["llm_explanation"] is None


# 整份報告可被 json.dumps（確認無不可序列化的物件，如 Path）
def test_report_is_json_serializable():
    report = build_report("foo/", 1, 4, [("foo/a.py", _finding())])
    text = json.dumps(report, ensure_ascii=False)
    assert json.loads(text)["summary"]["total"] == 1   # dump 再 load 一致
