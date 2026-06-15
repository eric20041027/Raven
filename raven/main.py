"""RAVEN CLI 入口。

用法：
    raven scan <path>      # path 可以是單一 .py 檔，或一個資料夾（遞迴掃所有 .py）

M1 範圍：只 Python、只一條規則（Hardcoded Secret）、純文字輸出。
"""
import pathlib
import click

from raven.parser.ast_parser import AstParser
from raven.rules import secret_rule


@click.group()
def cli() -> None:
    """RAVEN 🪶 — Risk Analysis & Vulnerability Examination Node"""
    # @click.group() 讓 raven 變成一個「指令群組」，底下可掛 scan 等子指令。
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
def scan(path: str) -> None:
    """掃描 PATH（單一檔案或資料夾）找出漏洞。"""
    # 1. 收集要掃的檔案：給檔案就掃它，給資料夾就遞迴找所有 .py
    targets = _collect_python_files(path)

    if not targets:
        click.echo("找不到任何 .py 檔可掃描。")
        return

    # 2. 對每個檔案跑規則，累積所有命中
    parser = AstParser()
    all_findings = []
    for file_path in targets:
        source = file_path.read_bytes()
        tree = parser.parse_source(source)
        findings = secret_rule.check(tree.root_node, source)
        # 每個 finding 記住它來自哪個檔（規則本身不知道檔名）
        for f in findings:
            all_findings.append((file_path, f))

    # 3. 印出報告
    _print_report(path, targets, all_findings)


def _collect_python_files(path: str) -> list[pathlib.Path]:
    """把輸入路徑展開成一串 .py 檔。"""
    p = pathlib.Path(path)
    if p.is_file():
        return [p] if p.suffix == ".py" else []
    # 是資料夾 → 遞迴找所有 .py（rglob = recursive glob）
    return sorted(p.rglob("*.py"))


def _print_report(scan_path, targets, all_findings) -> None:
    """純文字報告（M2 會升級成 rich 彩色）。"""
    click.echo("RAVEN v0.1.0  🪶  Risk Analysis & Vulnerability Examination Node\n")
    click.echo(f"掃描路徑：{scan_path}")
    click.echo(f"掃描檔案：{len(targets)} 個 .py")
    click.echo("─" * 52)

    for file_path, f in all_findings:
        click.echo(f"\n[{f.severity}]  Hardcoded Secret ({f.cwe})")
        click.echo(f"  檔案：{file_path}，第 {f.line} 行")
        click.echo(f"  程式碼：{f.snippet}")

    click.echo("\n" + "─" * 52)
    click.echo(f"掃描完成：發現 {len(all_findings)} 個漏洞")


if __name__ == "__main__":
    cli()
