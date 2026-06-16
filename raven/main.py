"""RAVEN CLI 入口。

用法：
    raven scan <path>      # path 可以是單一 .py 檔，或一個資料夾（遞迴掃所有 .py）

M2：CLI 走 YAML 規則引擎（取代 M1 寫死的 secret_rule）。
"""
import pathlib
import click

from raven.parser.ast_parser import AstParser
from raven.rules.engine import RuleEngine

# 規則定義資料夾（相對於套件位置，確保任何工作目錄下都找得到）
RULES_DIR = str(pathlib.Path(__file__).parent / "rules" / "definitions")


@click.group()
def cli() -> None:
    """RAVEN 🪶 — Risk Analysis & Vulnerability Examination Node"""
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
def scan(path: str) -> None:
    """掃描 PATH（單一檔案或資料夾）找出漏洞。"""
    targets = _collect_python_files(path)
    if not targets:
        click.echo("找不到任何 .py 檔可掃描。")
        return

    # 載入規則引擎（讀 definitions/ 下所有 YAML 規則）
    engine = RuleEngine.from_directory(RULES_DIR)
    parser = AstParser()

    all_findings = []
    for file_path in targets:
        source = file_path.read_bytes()
        tree = parser.parse_source(source)
        for f in engine.scan(tree.root_node, source):
            all_findings.append((file_path, f))

    _print_report(path, targets, len(engine.rules), all_findings)


def _collect_python_files(path: str) -> list[pathlib.Path]:
    """把輸入路徑展開成一串 .py 檔。"""
    p = pathlib.Path(path)
    if p.is_file():
        return [p] if p.suffix == ".py" else []
    return sorted(p.rglob("*.py"))


def _print_report(scan_path, targets, rule_count, all_findings) -> None:
    """純文字報告（M2 後段會升級成 rich 彩色）。"""
    click.echo("RAVEN v0.1.0  🪶  Risk Analysis & Vulnerability Examination Node\n")
    click.echo(f"掃描路徑：{scan_path}")
    click.echo(f"掃描檔案：{len(targets)} 個 .py")
    click.echo(f"掃描規則：{rule_count} 條")
    click.echo("─" * 52)

    for file_path, f in all_findings:
        click.echo(f"\n[{f.severity}]  {f.rule_id} ({f.cwe})")
        click.echo(f"  檔案：{file_path}，第 {f.line} 行")
        click.echo(f"  程式碼：{f.snippet}")
        click.echo(f"  ⚠ {f.message}")

    click.echo("\n" + "─" * 52)
    click.echo(f"掃描完成：發現 {len(all_findings)} 個漏洞")


if __name__ == "__main__":
    cli()
