"""RAVEN CLI 入口。

用法：
    raven scan <path>      # path 可以是單一 .py 檔，或一個資料夾（遞迴掃所有 .py）

M2：CLI 走 YAML 規則引擎（取代 M1 寫死的 secret_rule）。
"""
import pathlib
import click

from raven.parser.ast_parser import AstParser
from raven.rules.engine import RuleEngine
from raven.reporter import cli_reporter

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

    cli_reporter.print_report(path, len(targets), len(engine.rules), all_findings)


def _collect_python_files(path: str) -> list[pathlib.Path]:
    """把輸入路徑展開成一串 .py 檔。"""
    p = pathlib.Path(path)
    if p.is_file():
        return [p] if p.suffix == ".py" else []
    return sorted(p.rglob("*.py"))


if __name__ == "__main__":
    cli()
