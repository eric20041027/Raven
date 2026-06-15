# RAVEN 🪶
### Risk Analysis & Vulnerability Examination Node
##### 靜態程式碼漏洞掃描器 — 專案規劃文件

> **一句話描述：** 輸入任意 GitHub repo 或本地路徑，自動解析 AST、比對漏洞規則，並由本地 LLM（Qwen2.5-Coder via oMLX）產出人話說明與修補建議，全程離線、零雲端。

---

## 目錄

1. [專案概覽](#1-專案概覽)
2. [系統架構](#2-系統架構)
3. [目錄結構](#3-目錄結構)
4. [目標偵測漏洞](#4-目標偵測漏洞)
5. [四週 Milestone](#5-四週-milestone)
6. [技術選型與依賴](#6-技術選型與依賴)
7. [LLM 串接規格](#7-llm-串接規格)
8. [Prompt 設計](#8-prompt-設計)
9. [輸出規格](#9-輸出規格)
10. [學習資源](#10-學習資源)
11. [未來延伸方向](#11-未來延伸方向)

---

## 1. 專案概覽

| 項目 | 內容 |
|------|------|
| 專案名稱 | **RAVEN** （Risk Analysis & Vulnerability Examination Node） |
| 類型 | CLI 工具 + HTML 報告產生器 |
| 語言 | Python 3.11+ |
| 目標語言 | Python、JavaScript（可擴充 PHP、Go） |
| 推論後端 | oMLX（本地 OpenAI-compatible API） |
| 模型 | Qwen2.5-Coder-7B-Instruct 4bit（可升至 14B） |
| 硬體 | Apple M2 MacBook Pro 13"，16GB unified memory |
| 預計週期 | 4 週 |
| 學習目標 | AST 解析、SAST 概念、LLM structured prompting、資安規則設計 |

---

## 2. 系統架構

```
輸入層
  ├── GitHub URL  ──→  自動 git clone 至暫存目錄
  └── 本地路徑    ──→  直接讀取

        ↓

分析核心
  ├── AST Parser（tree-sitter）
  │     └── 語言偵測 → 載入對應 grammar → 產生 AST
  ├── 規則引擎
  │     ├── 載入 YAML 規則定義
  │     └── 在 AST 節點上執行 pattern matching
  └── LLM 解釋器（oMLX API）
        ├── 組裝 structured prompt
        ├── 呼叫 http://localhost:8000/v1/chat/completions
        └── 解析 JSON 輸出

        ↓

輸出層
  ├── CLI 報告（terminal 彩色輸出）
  ├── HTML 報告（可互動、可過濾）
  └── JSON 輸出（供 CI/CD 整合）
```

---

## 3. 目錄結構

```
raven/
├── raven/
│   ├── __init__.py
│   ├── main.py               # CLI 入口（Click）
│   ├── parser/
│   │   ├── __init__.py
│   │   ├── detector.py       # 語言偵測
│   │   └── ast_parser.py     # tree-sitter 封裝
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py         # pattern matching 核心
│   │   └── definitions/      # YAML 規則檔
│   │       ├── sql_injection.yml
│   │       ├── hardcoded_secret.yml
│   │       ├── command_injection.yml
│   │       ├── unsafe_eval.yml
│   │       ├── path_traversal.yml
│   │       ├── insecure_deserialization.yml
│   │       ├── weak_hash.yml
│   │       └── debug_leak.yml
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── client.py         # oMLX API 呼叫
│   │   └── prompts.py        # prompt 模板
│   └── reporter/
│       ├── __init__.py
│       ├── cli_reporter.py   # terminal 輸出
│       ├── html_reporter.py  # HTML 報告產生
│       └── templates/
│           └── report.html
├── tests/
│   ├── fixtures/             # 故意有漏洞的測試程式碼
│   │   ├── vuln_sql.py
│   │   ├── vuln_secrets.js
│   │   └── vuln_cmd.py
│   └── test_engine.py
├── pyproject.toml
├── README.md
└── .gitignore
```

---

## 4. 目標偵測漏洞

### 高嚴重度（High）

| 漏洞類型 | 說明 | 目標語言 | CWE |
|----------|------|----------|-----|
| SQL Injection | 字串拼接組成 SQL 查詢 | Python、JS、PHP | CWE-89 |
| Command Injection | 使用者輸入進入 `os.system`、`exec`、`child_process` | Python、Node.js | CWE-78 |
| Hardcoded Secret | 原始碼中的 API key、password、token | 任何語言 | CWE-798 |

### 中嚴重度（Medium）

| 漏洞類型 | 說明 | 目標語言 | CWE |
|----------|------|----------|-----|
| Unsafe `eval()` | 動態執行字串程式碼 | JavaScript | CWE-95 |
| Path Traversal | 未驗證的檔案路徑操作 | Python、JS | CWE-22 |
| Insecure Deserialization | 使用 `pickle.loads` 反序列化不可信資料 | Python | CWE-502 |
| Weak Hash Algorithm | 使用 MD5 / SHA1 做安全用途 | Python、JS | CWE-327 |
| Debug / Logging Leak | 敏感資訊印入 log | 任何語言 | CWE-532 |

---

## 5. 四週 Milestone

### Week 1 — 基礎骨架 + AST 解析

**目標：** 能把 Python / JS 程式碼解析成 AST 並遍歷節點。

**任務清單：**
- [ ] 初始化專案（`pyproject.toml`、virtual env）
- [ ] 安裝並設定 `tree-sitter`、`tree-sitter-python`、`tree-sitter-javascript`
- [ ] 實作語言偵測（`detector.py`）：依副檔名決定用哪個 grammar
- [ ] 實作 `ast_parser.py`：把原始碼解析成 AST，提供 `iter_nodes()` 遍歷器
- [ ] 實作 CLI 入口（`click`），支援 `raven scan <path>` 指令
- [ ] 寫測試：確認 AST 可以找到函式呼叫節點

**交付物：** 執行 `raven scan ./tests/fixtures/` 能印出所有函式呼叫清單

---

### Week 2 — 規則引擎 + 前三類漏洞

**目標：** 能對程式碼輸出帶行號的漏洞清單。

**任務清單：**
- [ ] 設計 YAML 規則格式（見下方規格）
- [ ] 實作 `engine.py`：載入 YAML 規則、在 AST 節點上執行 pattern matching
- [ ] 實作三條規則：`sql_injection.yml`、`hardcoded_secret.yml`、`command_injection.yml`
- [ ] 實作 `cli_reporter.py`：用 `rich` 套件輸出彩色命中結果
- [ ] 寫測試 fixtures（故意有漏洞的程式碼），確認規則正確命中

**YAML 規則格式範例：**

```yaml
# rules/definitions/sql_injection.yml
id: SQL-001
name: SQL Injection via string concatenation
severity: HIGH
cwe: CWE-89
languages: [python, javascript]
patterns:
  - type: function_call
    functions: [execute, query, raw]
    arg_contains: ["+", "format(", "f\"", "%s"]
message: "SQL 查詢直接拼接使用者輸入，可能導致 SQL Injection"
```

**交付物：** `raven scan ./tests/fixtures/` 輸出漏洞清單，含檔名、行號、嚴重程度

---

### Week 3 — LLM 解釋器 + GitHub 輸入

**目標：** 每個漏洞都有 LLM 產出的說明與修補建議；支援直接掃 GitHub repo。

**任務清單：**
- [ ] 實作 `client.py`：封裝 oMLX API 呼叫，自動 retry、timeout 處理
- [ ] 實作 `prompts.py`：漏洞解釋 prompt 模板（見第 8 節）
- [ ] 整合 LLM 輸出：解析 JSON response，附加到漏洞結果物件
- [ ] 實作 GitHub 輸入：偵測 URL 格式 → `git clone` 到 `/tmp/raven-{hash}/` → 掃完自動清理
- [ ] 加入 `--no-llm` flag：跳過 LLM 分析（快速掃描模式）
- [ ] 加入 `--lang` flag：指定只掃特定語言

**交付物：** `raven scan https://github.com/user/repo` 輸出含 LLM 解釋的漏洞報告

---

### Week 4 — HTML 報告 + 收尾

**目標：** 產出可展示的互動式 HTML 報告；補完剩餘規則；整理 README。

**任務清單：**
- [ ] 實作 `html_reporter.py`：產生 HTML 報告（含程式碼片段高亮、嚴重度過濾）
- [ ] 補完剩餘五條規則：`unsafe_eval`、`path_traversal`、`insecure_deserialization`、`weak_hash`、`debug_leak`
- [ ] 調整 prompt：根據 Week 3 測試結果優化輸出品質
- [ ] 加入 JSON 輸出模式（`--format json`）
- [ ] 撰寫 `README.md`：安裝步驟、使用範例、規則說明
- [ ] 錄製 demo GIF（用 `vhs` 或 `terminalizer`）

**交付物：** 完整可展示的 portfolio project，含 README、demo、HTML 報告範例

---

## 6. 技術選型與依賴

```toml
# pyproject.toml 核心依賴
[project]
name = "raven"
# RAVEN — Risk Analysis & Vulnerability Examination Node
requires-python = ">=3.11"

dependencies = [
    "tree-sitter>=0.23",
    "tree-sitter-python>=0.23",
    "tree-sitter-javascript>=0.23",
    "openai>=1.0",        # 用來呼叫 oMLX OpenAI-compatible API
    "pyyaml>=6.0",
    "click>=8.0",
    "rich>=13.0",         # terminal 彩色輸出
    "gitpython>=3.1",     # git clone GitHub repo
    "jinja2>=3.0",        # HTML 報告模板
]

[project.scripts]
raven = "raven.main:cli"  # run as: raven scan <path>
```

**安裝步驟：**

```bash
# 1. 建立 venv
python3.11 -m venv .venv && source .venv/bin/activate

# 2. 安裝依賴
pip install -e ".[dev]"

# 3. 確認 oMLX 正在執行
curl http://localhost:8000/v1/models

# 4. 測試掃描
raven scan ./tests/fixtures/
```

---

## 7. LLM 串接規格

oMLX 提供 OpenAI-compatible endpoint，串接方式如下：

```python
# raven/llm/client.py
from openai import OpenAI
import json

class LLMClient:
    def __init__(self, base_url="http://localhost:8000/v1", model="qwen2.5-coder-7b-instruct"):
        self.client = OpenAI(base_url=base_url, api_key="local")
        self.model = model

    def explain_vuln(self, vuln: dict) -> dict:
        """
        vuln = {
            "type": "SQL_INJECTION",
            "file": "auth.py",
            "line": 42,
            "snippet": "query = 'SELECT * FROM users WHERE id=' + user_input",
            "cwe": "CWE-89"
        }
        """
        from .prompts import build_vuln_prompt, SYSTEM_PROMPT

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_vuln_prompt(vuln)}
            ],
            temperature=0.1,   # 低 temperature，輸出穩定
            max_tokens=512,
            response_format={"type": "json_object"}  # 強制 JSON 輸出
        )

        raw = response.choices[0].message.content
        return json.loads(raw)
```

**模型升級策略：**
- 目前：`Qwen2.5-Coder-7B-Instruct` 4bit（~4.5GB，推論快）
- 若輸出品質不足：升至 `Qwen2.5-Coder-14B-Instruct` 4bit（~9GB，仍在 16GB 記憶體內）
- 升級方式：在 oMLX 介面下載新模型後，更改 `--model` 參數即可，不需改程式碼

---

## 8. Prompt 設計

### System Prompt

```
你是一位專業的資安審查員，專門分析程式碼中的安全漏洞。
每次回覆必須嚴格按照以下 JSON 格式輸出，不要輸出任何其他內容：

{
  "risk_level": "HIGH | MEDIUM | LOW",
  "why": "一句話說明這段程式碼的具體風險（繁體中文，50 字以內）",
  "attack_scenario": "攻擊者如何利用此漏洞的具體範例（繁體中文，80 字以內）",
  "fixed_code": "修正後的完整程式碼片段"
}
```

### User Prompt 模板

```python
# raven/llm/prompts.py

def build_vuln_prompt(vuln: dict) -> str:
    return f"""以下程式碼被偵測為可能的 {vuln['type']}（{vuln['cwe']}）：

檔案：{vuln['file']}，第 {vuln['line']} 行
語言：{vuln['language']}

```{vuln['language']}
{vuln['snippet']}
```

請輸出 JSON 分析報告。"""
```

### Prompt 調校技巧

- `temperature=0.1`：確保每次輸出穩定，不要有隨機創意
- 指定 CWE 編號：讓模型有明確的漏洞定義參考
- 限制字數：避免模型輸出過長，CLI 顯示會亂
- 使用 `response_format={"type": "json_object"}`：強制 JSON，減少 parse 失敗

---

## 9. 輸出規格

### CLI 輸出範例

```
RAVEN v0.1.0  🪶  Risk Analysis & Vulnerability Examination Node

掃描路徑：./my_project/
偵測語言：Python (12 files), JavaScript (3 files)
掃描規則：8 條
────────────────────────────────────────────────────

[HIGH]  SQL Injection (CWE-89)
  檔案：auth.py，第 42 行
  程式碼：query = "SELECT * FROM users WHERE id=" + user_input

  ⚠ 風險：攻擊者可透過 user_input 注入任意 SQL 指令，存取或刪除資料庫所有資料。
  攻擊範例：user_input = "1; DROP TABLE users; --"
  修正建議：使用參數化查詢，例如 cursor.execute("... WHERE id=?", (user_input,))

[HIGH]  Hardcoded Secret (CWE-798)
  檔案：config.py，第 8 行
  程式碼：API_KEY = "sk-prod-abc123def456"
  ...

────────────────────────────────────────────────────
掃描完成：發現 5 個漏洞（HIGH: 2，MEDIUM: 3）
報告已儲存：./raven_report.html
```

### JSON 輸出格式

```json
{
  "scan_meta": {
    "target": "./my_project/",
    "timestamp": "2025-06-15T12:00:00",
    "files_scanned": 15,
    "rules_applied": 8
  },
  "findings": [
    {
      "id": "SQL-001",
      "severity": "HIGH",
      "cwe": "CWE-89",
      "file": "auth.py",
      "line": 42,
      "snippet": "query = \"SELECT * FROM users WHERE id=\" + user_input",
      "llm_explanation": {
        "risk_level": "HIGH",
        "why": "直接拼接使用者輸入至 SQL 查詢，可被注入惡意指令",
        "attack_scenario": "輸入 `1; DROP TABLE users; --` 可刪除整個資料表",
        "fixed_code": "cursor.execute('SELECT * FROM users WHERE id=?', (user_input,))"
      }
    }
  ],
  "summary": {
    "total": 5,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 0
  }
}
```

---

## 10. 學習資源

### AST 與 tree-sitter
- [tree-sitter 官方文件](https://tree-sitter.github.io/tree-sitter/) — "Using Parsers" 章節是最快入門路徑
- [tree-sitter Playground](https://tree-sitter.github.io/tree-sitter/playground) — 在瀏覽器裡直接看 AST 結構，開發規則時必用
- [py-tree-sitter 文件](https://github.com/tree-sitter/py-tree-sitter) — Python binding 的 API 參考

### 資安規則設計
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — 規則設計的基準，前五條都可以做成規則
- [CWE Top 25](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html) — 用 CWE 編號讓報告更專業
- [Semgrep 開源規則庫](https://github.com/returntocorp/semgrep-rules) — 看業界怎麼定義 pattern，自己用 AST 實作學得更深

### LLM Prompting
- [OpenAI Prompt Engineering Guide](https://platform.openai.com/docs/guides/prompt-engineering) — structured output 技巧通用於所有 OpenAI-compatible API
- [Qwen2.5-Coder 模型卡](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct) — 了解模型的指令格式偏好

### Python 工具
- `rich` 套件文件 — terminal 彩色輸出
- `click` 套件文件 — CLI 介面設計
- `jinja2` 套件文件 — HTML 報告模板

---

## 11. 未來延伸方向

完成四週核心版本後，可以考慮的延伸：

**功能面**
- 支援更多語言：Go、PHP、Ruby
- 加入 taint analysis：追蹤資料從 source 到 sink 的流向（比 pattern matching 更精準）
- Pre-commit hook 整合：每次 commit 前自動掃描
- VS Code extension：在編輯器內即時標記漏洞

**技術面**
- 升級至 `Qwen2.5-Coder-14B` 4bit 提升解釋品質
- 加入 embedding-based 相似漏洞搜尋
- 支援 diff 模式：只掃 `git diff` 的變更部分（加快 CI 速度）

**可見度**
- 掃知名開源專案（找到真實漏洞）寫 write-up
- 提交到 [awesome-static-analysis](https://github.com/analysis-tools-dev/static-analysis) 列表

---

*文件最後更新：2026-06-15*
*專案狀態：規劃中*
