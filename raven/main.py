"""RAVEN CLI 入口。

用法：
    raven scan <path>      # path 可以是單一 .py 檔，或一個資料夾（遞迴掃所有 .py）
    raven scan <url>       # http(s) 的 GitHub repo URL，自動 clone 來掃、掃完清理

M2：CLI 走 YAML 規則引擎（取代 M1 寫死的 secret_rule）。
M5：支援 GitHub repo URL 輸入（見 raven/source.py）。
"""
import pathlib
import click

from raven.parser.ast_parser import AstParser, detect_language
from raven.rules.engine import RuleEngine
from raven.rules.taint import analyze, sink_lines
from raven.reporter import cli_reporter, json_reporter, html_reporter
from raven.llm.client import LLMClient, annotate_findings
from raven.config import load_llm_config
from raven.source import resolve_source, is_url

# 支援掃描的副檔名
_SUPPORTED_EXTS = {".py", ".js"}

# 預設忽略的目錄（依賴/系統目錄，不該掃 —— 業界共識）
_IGNORE_DIRS = {
    ".venv", "venv", "env", "node_modules", ".git",
    "__pycache__", ".pytest_cache", "dist", "build", ".egg-info",
}

# 規則定義資料夾（相對於套件位置，確保任何工作目錄下都找得到）
RULES_DIR = str(pathlib.Path(__file__).parent / "rules" / "definitions")


@click.group()
def cli() -> None:
    """RAVEN 🪶 — Risk Analysis & Vulnerability Examination Node"""
    pass


@cli.command()
@click.argument("target")
@click.option("--llm", is_flag=True, help="啟用本地 LLM 產生漏洞解釋（需後端，如 Ollama/oMLX）")
@click.option("--base-url", default=None, help="LLM 後端 URL（覆寫環境變數 RAVEN_LLM_BASE_URL）")
@click.option("--model", default=None, help="LLM 模型名（覆寫 RAVEN_LLM_MODEL）")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "html"]),
              default="text", help="輸出格式：text（彩色）/ json（機器可讀）/ html（可視化報告）")
@click.option("-o", "--output", "output_file", default=None,
              type=click.Path(), help="輸出檔路徑（html 格式建議指定，如 report.html）")
def scan(target: str, llm: bool, base_url: str | None, model: str | None,
         output_format: str, output_file: str | None) -> None:
    """掃描 TARGET 找出漏洞。

    TARGET 可以是本地檔案/資料夾，或 http(s) 的 GitHub repo URL
    （URL 會自動 clone 到暫存目錄掃描，掃完清理）。
    """
    if is_url(target):
        click.echo(f"📥 clone 中：{target}")

    # resolve_source：URL → clone 到暫存目錄並在離開時清理；本地路徑 → 原樣使用。
    try:
        with resolve_source(target) as scan_root:
            _scan_directory(target, scan_root, llm, base_url, model,
                            output_format, output_file)
    except Exception as exc:  # 來源解析失敗（非法 URL、clone 失敗等）
        raise click.ClickException(str(exc)) from exc


def _scan_directory(display_name: str, scan_root: str, llm: bool,
                    base_url: str | None, model: str | None,
                    output_format: str, output_file: str | None) -> None:
    """掃描 scan_root 下的原始碼並輸出報告。

    display_name 是報告標題用的名稱（URL 時顯示原始 URL，而非暫存路徑）。
    """
    targets = _collect_source_files(scan_root)
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
        # pattern matching（引擎依語言把概念名翻成實際節點名）
        pattern_findings = engine.scan(tree.root_node, source, language)
        # taint analysis（目前僅 Python）
        is_python = language == "python"
        taint_findings = analyze(tree.root_node, source) if is_python else []
        # taint 已裁決的 SQL sink 行（含它判定安全、刻意不報的行）
        decided_lines = sink_lines(tree.root_node, source) if is_python else set()
        # 合併：taint 裁決過的行，pattern SQL-001 一律讓位給 taint（taint 更準）
        merged = _merge_findings(pattern_findings, taint_findings, decided_lines)
        for f in merged:
            all_findings.append((file_path, f))

    # 可選的 LLM 解釋步驟（--llm 才啟用；client 為 None 時 annotate 原樣回傳）
    client = _build_llm_client(llm, base_url, model)
    findings_only = [f for _, f in all_findings]
    annotated = annotate_findings(findings_only, client)
    all_findings = list(zip((fp for fp, _ in all_findings), annotated))

    # 依格式輸出報告。
    if output_format == "html":
        _emit_html(display_name, len(targets), len(engine.rules),
                   all_findings, output_file)
        return
    reporter = json_reporter if output_format == "json" else cli_reporter
    reporter.print_report(display_name, len(targets), len(engine.rules), all_findings)


def _emit_html(display_name: str, file_count: int, rule_count: int,
               findings: list, output_file: str | None) -> None:
    """產 HTML 報告：有 -o 就寫檔，沒有就印到 stdout。"""
    document = html_reporter.print_report(
        display_name, file_count, rule_count, findings
    )
    if output_file:
        pathlib.Path(output_file).write_text(document, encoding="utf-8")
        click.echo(f"📄 HTML 報告已輸出：{output_file}")
    else:
        click.echo(document)


def _merge_findings(pattern_findings: list, taint_findings: list,
                    decided_lines: set[int]) -> list:
    """合併 pattern matching 與 taint 結果，去除重複/誤報的 SQL 漏洞。

    taint 比 pattern matching 準（懂 sanitizer / 參數化）：凡是 taint
    「裁決過」的 SQL sink 行（decided_lines），該行的 pattern SQL-001 一律
    讓位給 taint —— 包含 taint 判定為安全、刻意不報的行（否則 pattern 的
    結構誤報會漏出來）。其他規則（Secret/cmd/eval）不受影響。
    """
    kept_pattern = [
        f for f in pattern_findings
        if not (f.rule_id == "SQL-001" and f.line in decided_lines)
    ]
    return kept_pattern + taint_findings


def _build_llm_client(enabled: bool, base_url: str | None, model: str | None):
    """依 --llm 決定是否建立 LLMClient。未啟用回 None（annotate 會原樣略過）。"""
    if not enabled:
        return None
    cfg = load_llm_config(base_url=base_url, model=model)
    click.echo(f"🤖 LLM 解釋已啟用（{cfg.base_url} / {cfg.model}），分析中可能需要一些時間…")
    return LLMClient(base_url=cfg.base_url, model=cfg.model, api_key=cfg.api_key)


def _collect_source_files(path: str) -> list[pathlib.Path]:
    """把輸入路徑展開成一串支援的原始碼檔（.py / .js），跳過依賴目錄。"""
    p = pathlib.Path(path)
    if p.is_file():
        return [p] if p.suffix in _SUPPORTED_EXTS else []
    # 資料夾：遞迴找所有支援副檔名的檔，但排除依賴/系統目錄
    return sorted(
        f for f in p.rglob("*")
        if f.suffix in _SUPPORTED_EXTS and not _is_ignored(f)
    )


def _is_ignored(file_path: pathlib.Path) -> bool:
    """檔案路徑中是否含有任何忽略目錄。"""
    return any(part in _IGNORE_DIRS for part in file_path.parts)


if __name__ == "__main__":
    cli()
