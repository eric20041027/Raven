"""RAVEN CLI 入口。

用法：
    raven scan <path>      # path 可以是單一 .py 檔，或一個資料夾（遞迴掃所有 .py）

M2：CLI 走 YAML 規則引擎（取代 M1 寫死的 secret_rule）。
"""
import pathlib
import click

from raven.parser.ast_parser import AstParser, detect_language
from raven.rules.engine import RuleEngine
from raven.reporter import cli_reporter

# 支援掃描的副檔名
_SUPPORTED_EXTS = {".py", ".js"}

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
    targets = _collect_source_files(path)
    if not targets:
        click.echo("找不到任何可掃描的原始碼檔（.py / .js）。")
        return

    # 載入規則引擎（讀 definitions/ 下所有 YAML 規則）
    engine = RuleEngine.from_directory(RULES_DIR)

    all_findings = []
    for file_path in targets:
        # 依每個檔案的副檔名決定語言，建對應的 parser
        language = detect_language(str(file_path))
        if language is None:
            continue   # 不支援的語言跳過
        parser = AstParser(language)
        source = file_path.read_bytes()
        tree = parser.parse_source(source)
        # 把語言傳給引擎 —— 引擎據此把規則的概念名翻成該語言的實際節點名
        for f in engine.scan(tree.root_node, source, language):
            all_findings.append((file_path, f))

    cli_reporter.print_report(path, len(targets), len(engine.rules), all_findings)


def _collect_source_files(path: str) -> list[pathlib.Path]:
    """把輸入路徑展開成一串支援的原始碼檔（.py / .js）。"""
    p = pathlib.Path(path)
    if p.is_file():
        return [p] if p.suffix in _SUPPORTED_EXTS else []
    # 資料夾：遞迴找所有支援副檔名的檔
    return sorted(f for f in p.rglob("*") if f.suffix in _SUPPORTED_EXTS)


if __name__ == "__main__":
    cli()
