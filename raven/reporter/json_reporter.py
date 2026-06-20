"""JSON 報告輸出 —— 供 CI/CD 整合的機器可讀格式。

職責單一：把掃描結果轉成乾淨的 JSON（無彩色碼、無框線）。
對應計劃第 11 節的 JSON 規格。
"""
import json


def build_report(scan_path, file_count: int, rule_count: int, findings: list) -> dict:
    """組出完整報告的 dict（之後 dump 成 JSON）。findings 是 [(file_path, Finding), ...]。"""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for _, f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return {
        "scan_meta": {
            "target": str(scan_path),
            "files_scanned": file_count,
            "rules_applied": rule_count,
        },
        "findings": [_finding_to_dict(fp, f) for fp, f in findings],
        "summary": {"total": len(findings), **counts},
    }


def _finding_to_dict(file_path, f) -> dict:
    """把一個 (file_path, Finding) 轉成 dict。"""
    return {
        "file": str(file_path),
        "rule_id": f.rule_id,
        "severity": f.severity,
        "cwe": f.cwe,
        "line": f.line,
        "snippet": f.snippet,
        "message": f.message,
        "llm_explanation": f.llm_explanation,
    }


def print_report(scan_path, file_count: int, rule_count: int, findings: list) -> None:
    """印出 JSON 報告。ensure_ascii=False 讓中文正常顯示。"""
    report = build_report(scan_path, file_count, rule_count, findings)
    print(json.dumps(report, ensure_ascii=False, indent=2))
