# RAVEN 🪶
### Risk Analysis & Vulnerability Examination Node
##### 靜態程式碼漏洞掃描器 — 專案規劃文件（v2，垂直切片重排版）

> **一句話描述：** 輸入任意 GitHub repo 或本地路徑，自動解析 AST、比對漏洞規則，並由本地 LLM（Qwen2.5-Coder via oMLX 或 Ollama）產出人話說明與修補建議，全程離線、零雲端。
>
> **v2 說明：** 此版本由開發者本人（非 AI）逐項決策重排而成。相較 v1（見 `RAVEN_project_plan.original.md`），改採「垂直切片」里程碑、明確的可攜性架構、階梯式工程流程，並已完成關鍵風險驗證。

---

## 目錄

1. [專案定位與學習目標](#1-專案定位與學習目標)
2. [核心架構決策](#2-核心架構決策)
3. [系統架構](#3-系統架構)
4. [目錄結構](#4-目錄結構)
5. [目標偵測漏洞](#5-目標偵測漏洞)
6. [五階段里程碑](#6-五階段里程碑)
7. [工程流程（階梯式導入）](#7-工程流程階梯式導入)
8. [技術選型與依賴](#8-技術選型與依賴)
9. [LLM 串接規格](#9-llm-串接規格)
10. [Prompt 設計](#10-prompt-設計)
11. [輸出規格](#11-輸出規格)
12. [風險驗證記錄](#12-風險驗證記錄)
13. [學習資源](#13-學習資源)
14. [未來延伸方向](#14-未來延伸方向)

---

## 1. 專案定位與學習目標

| 項目 | 內容 |
|------|------|
| 專案名稱 | **RAVEN**（Risk Analysis & Vulnerability Examination Node） |
| 類型 | CLI 工具 + HTML 報告產生器 |
| 語言 | Python 3.11+（Homebrew 版，**非** Anaconda） |
| 目標語言 | Python、JavaScript（可擴充 PHP、Go） |
| 推論後端 | 可設定：oMLX（Mac 加速）或 Ollama（跨平台預設） |
| 模型 | Qwen2.5-Coder-7B-Instruct 4bit |
| 硬體 | Apple M2 MacBook Pro 13"，16GB unified memory |
| 預計週期 | **五個彈性階段**（學習品質 > 趕進度，死線可調整） |

### 定位

RAVEN 是一個**練功用的真實專案**——同時追求三個學習目標，三者並重：

1. **學技術**：AST 解析、SAST 概念（含 pattern matching 與 taint analysis）、LLM structured prompting
2. **學工程流程**：TDD、git workflow、CI（從沒做過 → 在這專案實際練起來）
3. **學自己規劃大專案**：本份計劃的每個決策由開發者親手拍板，過程本身即學習目標

> 履歷展示是次要副產品，不是主要驅動力。

---

## 2. 核心架構決策

這些是動手前已拍板的關鍵決策，後續所有實作都以此為準。

### 決策 A：LLM 後端可攜性（層級 2 + 層級 4 疊加）

**層級 2 — 後端可設定**：程式碼對著 OpenAI-compatible 格式寫，`base_url` / `api_key` / `model` 全做成設定。使用者可任選 oMLX（Mac）、Ollama（跨平台）或其他相容後端，只改設定、不改程式碼。

**層級 4 — LLM 為可選增強**：規則引擎是核心、必跑、零外部依賴；LLM 是可插拔的增強層，可缺席。沒有任何後端時，RAVEN 仍能用純規則引擎掃出漏洞並產出報告（只是少了 AI 白話解釋）。

> **依賴方向鐵律：** `reporter` 與 `engine` **絕不** import 死 `llm`；LLM 模組必須能「優雅地不存在」（graceful degradation）。

### 決策 B：里程碑採垂直切片（Walking Skeleton）

不橫向堆積木（先全做 parser、再全做 rules…），而是讓**每個里程碑都從頭貫穿到尾、能跑、能驗證價值**。M1 就打通最薄的端到端管線，之後逐步加厚。

### 決策 C：規則引擎深度

以 **pattern matching** 為基礎打穩，並在 **M4 用一條規則挑戰 taint analysis**，對比著學，理解 SAST 的精華（資料流分析）。

---

## 3. 系統架構

```
輸入層
  ├── GitHub URL  ──→  自動 git clone 至暫存目錄（掃完清理）
  └── 本地路徑    ──→  直接讀取

        ↓

分析核心（核心、必跑、零外部依賴）
  ├── AST Parser（tree-sitter）
  │     └── 語言偵測 → 載入對應 grammar → 產生 AST
  └── 規則引擎
        ├── 載入 YAML 規則定義（M2 起）
        ├── pattern matching（在 AST 節點上比對）
        └── taint analysis（M4，追蹤 source → sink）

        ↓

LLM 解釋器（可選增強層，可缺席）
  ├── 後端可設定：oMLX / Ollama / 其他 OpenAI-compatible
  ├── 組裝 structured prompt
  ├── 呼叫 {base_url}/v1/chat/completions（帶可選 api_key）
  └── 解析 JSON 輸出；失敗或無後端 → 優雅降級為純規則結果

        ↓

輸出層
  ├── CLI 報告（rich 彩色輸出）
  ├── HTML 報告（可互動、可過濾）
  └── JSON 輸出（供 CI/CD 整合）
```

---

## 4. 目錄結構

```
raven/
├── raven/
│   ├── __init__.py
│   ├── main.py               # CLI 入口（Click）
│   ├── config.py             # 後端設定（base_url/api_key/model）讀取
│   ├── parser/
│   │   ├── __init__.py
│   │   ├── detector.py       # 語言偵測
│   │   └── ast_parser.py     # tree-sitter 封裝、iter_nodes() 遍歷器
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py         # pattern matching 核心
│   │   ├── taint.py          # taint analysis（M4）
│   │   └── definitions/      # YAML 規則檔（M2 起）
│   │       ├── hardcoded_secret.yml
│   │       ├── sql_injection.yml
│   │       ├── command_injection.yml
│   │       ├── unsafe_eval.yml
│   │       ├── path_traversal.yml
│   │       ├── insecure_deserialization.yml
│   │       ├── weak_hash.yml
│   │       └── debug_leak.yml
│   ├── llm/                  # 可選增強層，可缺席
│   │   ├── __init__.py
│   │   ├── client.py         # 後端 API 呼叫（base_url/api_key/model 可設定）
│   │   └── prompts.py        # prompt 模板
│   └── reporter/
│       ├── __init__.py
│       ├── cli_reporter.py   # terminal 輸出
│       ├── html_reporter.py  # HTML 報告產生
│       └── templates/
│           └── report.html
├── tests/
│   ├── fixtures/             # 故意有漏洞的測試程式碼
│   └── test_*.py
├── .github/workflows/        # CI（M5）
├── pyproject.toml
├── README.md
└── .gitignore
```

---

## 5. 目標偵測漏洞

### 高嚴重度（High）

| 漏洞類型 | 說明 | 目標語言 | CWE | 偵測法 |
|----------|------|----------|-----|--------|
| Hardcoded Secret | 原始碼中的 API key、password、token | 任何語言 | CWE-798 | pattern（M1 第一條規則） |
| SQL Injection | 字串拼接組成 SQL 查詢 | Python、JS | CWE-89 | pattern + **taint（M4）** |
| Command Injection | 使用者輸入進入 `os.system`、`exec` | Python、Node.js | CWE-78 | pattern + 可選 taint |

### 中嚴重度（Medium）

| 漏洞類型 | 說明 | 目標語言 | CWE |
|----------|------|----------|-----|
| Unsafe `eval()` | 動態執行字串程式碼 | JavaScript | CWE-95 |
| Path Traversal | 未驗證的檔案路徑操作 | Python、JS | CWE-22 |
| Insecure Deserialization | `pickle.loads` 反序列化不可信資料 | Python | CWE-502 |
| Weak Hash Algorithm | MD5 / SHA1 做安全用途 | Python、JS | CWE-327 |
| Debug / Logging Leak | 敏感資訊印入 log | 任何語言 | CWE-532 |

---

## 6. 五階段里程碑

> 結構：垂直切片。每階段皆可獨立運行與驗證。依賴關係見下圖。

```
M1 → M2 ─┬→ M3 (LLM 解釋) ──┐
         └→ M4 (taint 分析) ─┴→ M5 (收尾)
         （M3 與 M4 互不依賴，可對調順序或並行；卡關時可互相換手）
```

### M1 — Walking Skeleton：打通最薄管線

**目標：** 讓「讀檔 → AST → 一條規則 → 找到漏洞 → 印出來」整條管線的每個關節都連起來、能動。

**範圍刻意限制（為了夠薄）：**
- 只支援 Python（不碰 JS）
- 只有一條規則：Hardcoded Secret
- 只有 CLI 純文字輸出（不碰 rich、HTML、LLM）
- 規則**直接寫死在 Python**（不做 YAML —— YAGNI，延到 M2）

**任務：**
- [ ] 初始化專案（`pyproject.toml`、venv 用 Homebrew python3.11）
- [ ] 安裝設定 `tree-sitter`、`tree-sitter-python`
- [ ] `detector.py`：依副檔名偵測語言
- [ ] `ast_parser.py`：原始碼 → AST，提供 `iter_nodes()` 遍歷器
- [ ] 寫死的 Hardcoded Secret 規則：找賦值節點 + 字串符合密鑰特徵
- [ ] CLI 入口（click）：`raven scan <path>`
- [ ] **事後測試**：確認骨架能正確抓到密鑰（先不強求 TDD，專心摸懂 tree-sitter）

**交付物：** `raven scan vuln.py` 能印出 `[HIGH] Hardcoded Secret @ vuln.py:8`

**學習重點：** tree-sitter 基礎、AST 遍歷、第一次「在語法樹上定位節點」

---

### M2 — 加厚管線：規則引擎 + 多規則 + 多語言

**目標：** 從「一條寫死的規則」長成「可設定的規則引擎」，支援多語言、彩色輸出。

**任務：**
- [ ] **從寫死重構成 YAML**：設計 YAML 規則格式、做 `engine.py` 載入並執行 pattern matching（親身體會「為什麼需要抽象」）
- [ ] 補 pattern-matching 規則：SQL Injection、Command Injection、unsafe eval 等
- [ ] 加 JavaScript 支援（`tree-sitter-javascript`）
- [ ] `cli_reporter.py`：rich 彩色輸出
- [ ] **正式練 TDD**：每條新規則「先寫有漏洞的 fixture + 預期結果，再實作規則」（規則引擎是 TDD 甜蜜點）

**交付物：** `raven scan` 用多條規則掃 Python + JS，彩色列出多個帶行號的漏洞

**學習重點：** 規則引擎設計、YAML 抽象、TDD 完整循環

---

### M3 — LLM 解釋層（可選增強）

**目標：** 每個漏洞附 LLM 白話解釋；後端可設定；無後端時優雅降級。

**任務：**
- [ ] `client.py`：`LLMClient`，`base_url`/`api_key`/`model` 皆可設定（oMLX 需 `Authorization: Bearer key`，Ollama 不需 key）、retry/timeout 處理
- [ ] `prompts.py`：漏洞解釋 prompt 模板
- [ ] 整合：解析 JSON response 附加到漏洞結果物件
- [ ] `--no-llm` flag + 優雅降級：無後端／呼叫失敗時仍輸出純規則結果
- [ ] **測試降級邏輯**（沒後端會怎樣）；LLM 輸出本身用寬鬆斷言（每次回應略有不同）

**交付物：** `raven scan` 每個漏洞附 LLM 解釋；拔掉後端仍能純規則掃並出報告

**學習重點：** LLM 串接、structured output、介面抽象、graceful degradation

---

### M4 — Taint Analysis 挑戰

**目標：** 挑一條規則用資料流分析重做，對比 pattern matching，理解 SAST 精華。專注單一技術挑戰，**不混入收尾雜事**。

**任務：**
- [ ] 選定一條規則（SQL Injection 或 Command Injection）
- [ ] `taint.py`：標記 source（使用者輸入）、追蹤污點傳播、偵測流入 sink（危險函式）
- [ ] 與該規則的 pattern-matching 版本對比，記錄「準度差異 / 誤報差異」

**交付物：** 一條可運作的 taint-analysis 規則 + 與 pattern matching 的對比說明

**學習重點：** 資料流分析（source → sink）、SAST 進階核心

---

### M5 — 收尾：報告 / 輸出 / 輸入 / 文件

**目標：** 把工具打磨成完整可展示的開源專案。

**任務：**
- [ ] `html_reporter.py`：HTML 報告（程式碼高亮、嚴重度過濾）
- [ ] JSON 輸出模式（`--format json`）
- [ ] GitHub 輸入：偵測 URL → `git clone` 到暫存目錄 → 掃完清理
- [ ] `README.md`：安裝步驟（**含 Ollama 跨平台 + oMLX Mac 加速雙後端說明**）、使用範例、規則說明
- [ ] **導入 CI**（GitHub Actions：每次 push 自動跑測試）
- [ ] 錄製 demo GIF

**交付物：** 完整可展示的 portfolio project，含 README、CI、demo、HTML 報告範例

**學習重點：** HTML 報告、開源收尾、跨平台部署文件、CI 自動化

---

## 7. 工程流程（階梯式導入）

在「最適合學它的時機」導入對應流程，而非全程教條套用：

| 階段 | 工程流程 | 理由 |
|------|----------|------|
| M1 | 事後測試 | 摸索 tree-sitter 期間硬上 TDD 會卡死；先學會寫測試的機制 |
| M2 | **正式 TDD** | 規則引擎需求明確（輸入 code → 預期漏洞），TDD 甜蜜點 |
| M3 | 測降級邏輯 + 寬鬆斷言 | LLM 輸出非確定性，測「無後端時的行為」比測輸出內容有意義 |
| M5 | **CI（GitHub Actions）** | 此時已累積一批測試，可自動化串起來 |
| 全程 | git workflow | conventional commits、feature branch、PR |

---

## 8. 技術選型與依賴

```toml
# pyproject.toml 核心依賴
[project]
name = "raven"
requires-python = ">=3.11"

dependencies = [
    "tree-sitter>=0.23",
    "tree-sitter-python>=0.23",
    "tree-sitter-javascript>=0.23",   # M2
    "openai>=1.0",        # 呼叫 OpenAI-compatible API（oMLX / Ollama）
    "pyyaml>=6.0",        # M2：YAML 規則
    "click>=8.0",
    "rich>=13.0",         # M2：terminal 彩色輸出
    "gitpython>=3.1",     # M5：git clone GitHub repo
    "jinja2>=3.0",        # M5：HTML 報告模板
]

[project.scripts]
raven = "raven.main:cli"
```

**安裝步驟：**

```bash
# 1. 建立 venv（務必用 Homebrew python3.11，非 Anaconda）
/opt/homebrew/bin/python3.11 -m venv .venv && source .venv/bin/activate

# 2. 安裝依賴
pip install -e ".[dev]"

# 3. 確認後端（擇一）
#    oMLX（Mac）：
curl -H "Authorization: Bearer <key>" http://localhost:8000/v1/models
#    Ollama（跨平台）：
curl http://localhost:11434/api/tags

# 4. 測試掃描
raven scan ./tests/fixtures/
```

---

## 9. LLM 串接規格

後端可設定，對著 OpenAI-compatible endpoint 串接。**`base_url`、`api_key`、`model` 全可設定**——這是已驗證的需求（oMLX 要 key、Ollama 不要）。

```python
# raven/llm/client.py
from openai import OpenAI
import json

class LLMClient:
    def __init__(self, base_url=None, api_key=None, model=None):
        # 全部可由 config / 環境變數覆寫
        # oMLX  : base_url=http://localhost:8000/v1, api_key=<key 必填>
        # Ollama: base_url=http://localhost:11434/v1, api_key 可省略
        self.client = OpenAI(base_url=base_url, api_key=api_key or "not-needed")
        self.model = model

    def explain_vuln(self, vuln: dict) -> dict | None:
        """回傳 LLM 解釋；任何失敗回 None → 由上層優雅降級為純規則結果。"""
        from .prompts import build_vuln_prompt, SYSTEM_PROMPT
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_vuln_prompt(vuln)},
                ],
                temperature=0.1,
                max_tokens=512,
                response_format={"type": "json_object"},
            )
            return json.loads(response.choices[0].message.content)
        except Exception:
            return None   # 優雅降級：不讓 LLM 失敗拖垮整個掃描
```

**效能認知（來自 R1 驗證）：** 模型首次呼叫含一次性載入成本（oMLX 實測 ~3.68s），之後每次純推論約 4–5s（7B@M2，~19 tok/s）。掃大 repo 時 LLM 解釋會是瓶頸 → 這正是「LLM 可選、純規則必跑」設計的現實依據。

**模型升級策略：** 7B 不夠時可升 14B 4bit（~9GB，仍在 16GB 內），只改 `--model` 參數。

---

## 10. Prompt 設計

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
def build_vuln_prompt(vuln: dict) -> str:
    return f"""以下程式碼被偵測為可能的 {vuln['type']}（{vuln['cwe']}）：

檔案：{vuln['file']}，第 {vuln['line']} 行
語言：{vuln['language']}

```{vuln['language']}
{vuln['snippet']}
```

請輸出 JSON 分析報告。"""
```

### 調校技巧
- `temperature=0.1`：輸出穩定
- 指定 CWE 編號：給模型明確漏洞定義參考
- 限制字數：避免 CLI 顯示爆版
- `response_format={"type":"json_object"}`：強制 JSON（已驗證 oMLX 與 Ollama 皆支援）

---

## 11. 輸出規格

### CLI 輸出範例

```
RAVEN v0.1.0  🪶  Risk Analysis & Vulnerability Examination Node

掃描路徑：./my_project/
偵測語言：Python (12 files), JavaScript (3 files)
掃描規則：8 條
────────────────────────────────────────────────────

[HIGH]  Hardcoded Secret (CWE-798)
  檔案：config.py，第 8 行
  程式碼：API_KEY = "sk-prod-abc123def456"

  ⚠ 風險：密鑰寫死於原始碼，任何能讀到程式碼的人都能取得正式環境憑證。
  修正建議：改用環境變數 os.environ["API_KEY"]，並將密鑰移出版本控制。

────────────────────────────────────────────────────
掃描完成：發現 5 個漏洞（HIGH: 2，MEDIUM: 3）
報告已儲存：./raven_report.html
```

### JSON 輸出格式

```json
{
  "scan_meta": {
    "target": "./my_project/",
    "timestamp": "2026-06-15T12:00:00",
    "files_scanned": 15,
    "rules_applied": 8,
    "llm_backend": "ollama"
  },
  "findings": [
    {
      "id": "SECRET-001",
      "severity": "HIGH",
      "cwe": "CWE-798",
      "file": "config.py",
      "line": 8,
      "snippet": "API_KEY = \"sk-prod-abc123def456\"",
      "detection": "pattern",
      "llm_explanation": {
        "risk_level": "HIGH",
        "why": "密鑰寫死於原始碼，可被任何讀到程式碼者取得",
        "attack_scenario": "攻擊者從公開 repo 抓到 key 後直接呼叫正式 API",
        "fixed_code": "API_KEY = os.environ['API_KEY']"
      }
    }
  ],
  "summary": { "total": 5, "HIGH": 2, "MEDIUM": 3, "LOW": 0 }
}
```

> 注意：`llm_explanation` 在無後端（純規則模式）時為 `null`，報告仍完整輸出。

---

## 12. 風險驗證記錄

> de-risking：動手前先用最少成本消除最大未知。

### R1 — LLM 後端可行性 ✅ 已驗證關閉（2026-06-15）

最大風險：若本地 LLM 在 M2/16GB 上跑不動或太慢，「本地 LLM 解釋」這個核心賣點不成立，整個架構要重想。**已用同一測試（SQL injection + 強制 JSON）實測兩條後端：**

| | oMLX (8000) | Ollama (11434) |
|---|---|---|
| 連線 | ✅ HTTP 200（需 Bearer key） | ✅ HTTP 200（無需 key） |
| JSON 強制輸出 | ✅ 合法 | ✅ 合法 |
| 漏洞判斷 | ✅ 正確抓 SQLi + 參數化修法 | ✅ 正確抓 SQLi + 參數化修法 |
| 速度 | ~19 tok/s，首次含 3.68s 載入 | ~10.6s（GPU Metal 加速） |

**結論：** 架構成立。實證了「後端可設定」設計，並發現「oMLX 需 key、Ollama 不需」→ `LLMClient` 的 `api_key` 必須可設定。

### 其餘已知風險（未來追蹤）

- R2 tree-sitter 學習曲線（M1 處理）
- R3 規則引擎準度／誤報（M2 處理，M4 用 taint 改善）
- R4 LLM 7B 輸出品質（M3 處理，必要時升 14B）

---

## 13. 學習資源

### AST 與 tree-sitter
- [tree-sitter 官方文件](https://tree-sitter.github.io/tree-sitter/) — "Using Parsers" 章節
- [tree-sitter Playground](https://tree-sitter.github.io/tree-sitter/playground) — 瀏覽器裡直接看 AST，開發規則必用
- [py-tree-sitter 文件](https://github.com/tree-sitter/py-tree-sitter)

### 資安規則設計
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html)
- [Semgrep 開源規則庫](https://github.com/returntocorp/semgrep-rules) — 看業界怎麼定義 pattern
- Taint analysis 入門（M4 前再深入）：搜尋 "static taint analysis source sink dataflow"

### LLM Prompting
- [OpenAI Prompt Engineering Guide](https://platform.openai.com/docs/guides/prompt-engineering)
- [Qwen2.5-Coder 模型卡](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct)

### Python 工具
- `rich`、`click`、`jinja2` 套件文件

---

## 14. 未來延伸方向

**功能面**
- 更多語言：Go、PHP、Ruby
- 把 taint analysis 從「一條規則」推廣到多條規則
- Pre-commit hook 整合；VS Code extension 即時標記
- 後端自動偵測（層級 3）：自動發現使用者裝了哪個後端、零設定

**技術面**
- 升級至 Qwen2.5-Coder-14B 4bit
- embedding-based 相似漏洞搜尋
- diff 模式：只掃 `git diff` 變更部分（加快 CI）

**可見度**
- 掃知名開源專案找真實漏洞、寫 write-up
- 提交到 [awesome-static-analysis](https://github.com/analysis-tools-dev/static-analysis)

---

*文件最後更新：2026-06-15*
*專案狀態：規劃完成，準備進入 M1*
*v1 原版備份：`RAVEN_project_plan.original.md`*
