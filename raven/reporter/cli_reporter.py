"""CLI 報告輸出（rich 彩色版）。

職責單一：只負責「把掃描結果漂亮地呈現到終端機」。
掃描流程在 main.py，這裡完全不碰掃描邏輯 —— 輸出與邏輯分離。
"""
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# 嚴重度 → 顏色，集中定義方便調整
_SEVERITY_COLOR = {
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
}

console = Console()


def print_report(scan_path, file_count: int, rule_count: int, findings: list) -> None:
    """印出完整掃描報告。findings 是 [(file_path, Finding), ...]。"""
    # 標題
    console.print("\n[bold]RAVEN[/bold] 🪶  Risk Analysis & Vulnerability Examination Node\n")

    # 掃描摘要
    console.print(f"掃描路徑：[cyan]{scan_path}[/cyan]")
    console.print(f"掃描檔案：{file_count} 個　掃描規則：{rule_count} 條")

    if not findings:
        console.print("\n[bold green]✓ 沒有發現漏洞[/bold green]\n")
        return

    # 每個漏洞用一個彩色面板呈現
    for file_path, f in findings:
        _print_finding(file_path, f)

    # 統計摘要（依嚴重度分類計數）
    _print_summary(findings)


def _print_finding(file_path, f) -> None:
    """單一漏洞 → 一個彩色面板。"""
    color = _SEVERITY_COLOR.get(f.severity, "white")

    body = Text()
    body.append(f"檔案：{file_path}，第 {f.line} 行\n", style="dim")
    body.append(f"{f.snippet}\n", style="white")
    body.append(f"⚠ {f.message}", style=color)

    # 有 LLM 解釋才顯示（無 LLM 時略過，優雅降級的呈現面）
    exp = f.llm_explanation
    if exp:
        body.append("\n\n🤖 AI 分析：\n", style="bold cyan")
        if exp.get("why"):
            body.append(f"  風險：{exp['why']}\n", style="white")
        if exp.get("attack_scenario"):
            body.append(f"  攻擊：{exp['attack_scenario']}\n", style="white")
        if exp.get("fixed_code"):
            body.append(f"  修正：{exp['fixed_code']}", style="green")

    # 面板標題顯示嚴重度與規則編號，邊框用嚴重度顏色
    title = f"[{color}][{f.severity}][/{color}] {f.rule_id} ({f.cwe})"
    console.print(Panel(body, title=title, title_align="left", border_style=color))


def _print_summary(findings: list) -> None:
    """依嚴重度統計，印出總結行。"""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for _, f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    total = len(findings)
    console.print(
        f"\n掃描完成：發現 [bold]{total}[/bold] 個漏洞　"
        f"([red]HIGH: {counts['HIGH']}[/red]，"
        f"[yellow]MEDIUM: {counts['MEDIUM']}[/yellow]，"
        f"[cyan]LOW: {counts['LOW']}[/cyan])\n"
    )
