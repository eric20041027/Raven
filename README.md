# RAVEN 🪶

[![CI](https://github.com/eric20041027/Raven/actions/workflows/ci.yml/badge.svg)](https://github.com/eric20041027/Raven/actions/workflows/ci.yml)

### Risk Analysis & Vulnerability Examination Node

> 本地 LLM 驅動的靜態程式碼漏洞掃描器（SAST）。輸入本地路徑或 GitHub repo URL，自動解析 AST、比對漏洞規則、追蹤污染資料流，並（可選）由本地 LLM 產出人話說明與修補建議——**全程離線、零雲端**。

---

## 這是什麼

RAVEN 用 [tree-sitter](https://tree-sitter.github.io/tree-sitter/) 把程式碼解析成抽象語法樹（AST），在樹上以兩種互補方式找漏洞：

1. **Pattern matching** — YAML 定義的規則直接比對 AST 節點結構，並支援 Shannon 熵判斷（抓「看起來像亂碼」的密鑰）。
2. **Taint analysis** — 追蹤使用者輸入（source）是否經資料流抵達危險函式（sink）、中途是否經 sanitizer 洗白，比純語法比對更準、誤報更少。

可選地，它會把命中的漏洞丟給本地 LLM（透過 OpenAI-compatible API，如 Ollama 或 oMLX）產生白話風險說明與修補建議。

**設計原則：**
- **規則引擎為核心、必跑、零外部依賴**——沒有 LLM 後端也能掃出漏洞
- **LLM 為可選增強層**——後端可設定（`base_url` / `api_key` / `model`），可缺席時優雅降級
- **資料驅動規則**——新增 pattern 規則 = 寫一個 YAML 檔，不用改程式碼

---

## ⚠️ 專案定位

RAVEN 是一個**學習導向的實驗性專案**，用來實作並理解 SAST 的核心概念（AST 解析、規則引擎、taint analysis、LLM 整合）。它**不是生產級工具**，請勿用於真實的安全稽核或在正式環境取代成熟的 SAST 產品。

偵測能力刻意保持精簡與透明：規則集小、taint analysis 涵蓋單一函式內到跨函式（inter-procedural）的污染追蹤，目的是把每個概念實作清楚、可驗證，而非追求覆蓋率。

---

## 安裝

本專案使用 [uv](https://github.com/astral-sh/uv) 管理 Python 環境。

```bash
# 1. 安裝 uv（若尚未安裝）
brew install uv          # macOS
# 或見 https://github.com/astral-sh/uv 的其他平台方式

# 2. clone 專案
git clone https://github.com/eric20041027/Raven.git
cd Raven

# 3. 建立環境並安裝
uv venv --python 3.11 .venv
uv pip install -e ".[dev]"
```

---

## 使用

```bash
# 掃描單一檔案
.venv/bin/raven scan path/to/file.py

# 掃描整個資料夾（遞迴掃所有 .py / .js）
.venv/bin/raven scan path/to/project/

# 掃描 GitHub repo（自動 clone 到暫存目錄、掃完清理）
.venv/bin/raven scan https://github.com/user/repo.git

# 試掃內建的範例漏洞檔
.venv/bin/raven scan tests/fixtures/
```

### 輸出格式

```bash
# 終端機彩色輸出（預設）
.venv/bin/raven scan tests/fixtures/ --format text

# 機器可讀的 JSON
.venv/bin/raven scan tests/fixtures/ --format json

# 自包含、可互動的 HTML 報告（嚴重度過濾 + 程式碼高亮）
.venv/bin/raven scan tests/fixtures/ --format html -o report.html
```

### 啟用 LLM 解釋（可選）

```bash
.venv/bin/raven scan tests/fixtures/ --llm
```

文字輸出範例：

```
╭─ [HIGH] SQL-TAINT-001 (CWE-89) ──────────────────────────────────────────────╮
│ 檔案：tests/fixtures/vuln_sqli.py，第 4 行                                   │
│ cursor.execute("SELECT * FROM users WHERE id=" + user_input)                 │
│ ⚠ 使用者輸入經資料流流入 SQL 查詢（taint 分析確認 source→sink）              │
╰──────────────────────────────────────────────────────────────────────────────╯

掃描完成：發現 8 個漏洞　(HIGH: 6，MEDIUM: 2，LOW: 0)
```

HTML 報告為**單一自包含檔案**：CSS / JS 全內嵌、Pygments 程式碼高亮寫死進檔案、不依賴任何 CDN，離線打開即可使用，並可在瀏覽器端按嚴重度即時過濾。

---

## 掃描 GitHub repo 的安全邊界

`raven scan <url>` 把工具指向了任意網路輸入，因此 clone 流程刻意設了防線：

- **只接受 `http(s)` URL**——擋掉 `git@` / `ssh://` / `file://`，避免存取本機檔案系統或誤用本機 SSH 金鑰。
- **淺層 clone（`--depth 1`）**——只抓最新一版，省時省空間。
- **超時保護**——clone 設有逾時上限，避免惡意或超大 repo 卡死。
- **保證清理**——clone 進 `tempfile` 暫存目錄，用 context manager 確保離開時刪除，即使掃描中途出錯。

---

## 規則格式

Pattern matching 規則定義在 `raven/rules/definitions/*.yml`，每個檔一條規則。引擎會自動載入該資料夾下所有規則。

```yaml
id: SECRET-001
name: Hardcoded Secret
severity: HIGH
cwe: CWE-798
message: 密鑰寫死於原始碼，任何能讀到程式碼的人都能取得憑證。建議改用環境變數。

match:
  node_type: assignment        # 找「賦值」AST 節點
  right_type: string           # 右邊必須是字串（排除 os.environ[...] 等安全寫法）
  any_of:                      # 以下任一成立即命中（高精度信號）
    - name_contains: [key, password, secret, token, api]   # 變數名含關鍵字
    - value_prefix: [sk-, ghp_, xox, AKIA]                 # 字串值符合已知前綴
  all_of:                      # 兜底信號：全部成立才命中（「且」）
    - value_entropy_min: 4.2   # Shannon 熵夠高（看起來像亂碼）
    - value_min_length: 20     # 且夠長（短亂碼多半不是密鑰）
```

支援的 `match` 條件：

| 條件 | 意義 |
|------|------|
| `node_type` / `right_type` | 結構條件（找哪種 AST 節點） |
| `name_contains` | 變數名含任一關鍵字 |
| `value_prefix` | 字串值符合任一已知前綴 |
| `value_min_length` | 字串值長度達標 |
| `value_entropy_min` | 字串值的 Shannon 熵達標（亂度信號） |

`any_of`（任一成立）與 `all_of`（全部成立）可並存，為「或」關係——任一群命中即報。

> **為什麼用熵 + 長度雙條件**：單看長度會把 URL / 模型名 / prompt 都誤判成密鑰；單看熵又擋不掉 URL（URL 的熵也偏高）。實測中真密鑰與一般字串的熵範圍重疊，故採「夠亂 **且** 夠長」雙條件，比單一閾值穩。

**新增規則**：在 `definitions/` 下新增一個 `.yml` 檔即可，無需改程式碼。

---

## LLM 後端（可選）

RAVEN 的 LLM 解釋層支援任何 OpenAI-compatible 後端，後端可設定：

| 後端 | 平台 | Endpoint | 需要 API key |
|------|------|----------|-------------|
| [Ollama](https://ollama.com/) | 跨平台（推薦預設） | `http://localhost:11434/v1` | 否 |
| oMLX | macOS / Apple Silicon | `http://localhost:8000/v1` | 是 |

後端設定可透過三種方式提供（優先級：CLI 旗標 > 環境變數 > 內建預設）：

| 環境變數 | CLI 旗標 | 說明 | 預設 |
|----------|---------|------|------|
| `RAVEN_LLM_BASE_URL` | `--base-url` | 後端 endpoint | `http://localhost:11434/v1`（Ollama） |
| `RAVEN_LLM_MODEL` | `--model` | 模型名 | `qwen2.5-coder:7b` |
| `RAVEN_LLM_API_KEY` | （無，僅環境變數） | API key | 無（Ollama 不需；oMLX 必填） |

> API key 只能透過環境變數提供、不開放 CLI 旗標，避免金鑰出現在 shell 命令歷史中（安全考量）。

### Ollama（預設，免 key）

```bash
# 1. 啟動 Ollama 並拉模型
ollama pull qwen2.5-coder:7b
ollama serve

# 2. 掃描（base-url 用預設，可省略）
.venv/bin/raven scan src/ --llm --model qwen2.5-coder:7b
```

### oMLX（macOS / Apple Silicon，需 key）

oMLX 是 OpenAI-compatible 後端，RAVEN 以標準 `Authorization: Bearer <key>` 認證連接。

```bash
# 1. 啟動 oMLX 服務（依你的安裝方式，預設 endpoint 為 :8000）
#    服務會提供一把 API key

# 2. 用環境變數提供 key，再掃描
export RAVEN_LLM_API_KEY="your-omlx-key"
.venv/bin/raven scan src/ --llm \
  --base-url http://localhost:8000/v1 \
  --model <你的 oMLX 模型名>
```

也可把整組設定都放進環境變數，CLI 就只需 `--llm`：

```bash
export RAVEN_LLM_BASE_URL="http://localhost:8000/v1"
export RAVEN_LLM_MODEL="<你的 oMLX 模型名>"
export RAVEN_LLM_API_KEY="your-omlx-key"
.venv/bin/raven scan src/ --llm
```

> LLM 層為**可選增強**——沒有後端時，RAVEN 仍以純規則引擎運作（不傳 key 時 Ollama 仍可用）。

---

## 偵測能力

| 漏洞 | CWE | 偵測法 | 狀態 |
|------|-----|--------|------|
| Hardcoded Secret | CWE-798 | pattern matching + Shannon 熵 | ✅ |
| SQL Injection | CWE-89 | pattern + taint（單函式 + 跨函式，含 sanitizer 感知） | ✅ |
| Command Injection | CWE-78 | pattern matching | ✅ |
| Unsafe eval | CWE-95 | pattern matching | ✅ |

支援語言：**Python**（pattern + taint）、**JavaScript**（pattern）。

taint analysis 的資料流模型：**source**（函式參數、輸入函式）→ **sanitizer**（`escape`/`quote` 等洗白）→ **sink**（`execute`/`query` 等）。髒資料經 sanitizer 洗白後不再視為危險。

涵蓋兩個層次：
- **單函式內（intra-procedural）**：含 sanitizer 感知、參數化查詢辨識。
- **跨函式（inter-procedural）**：用 function summary（函式摘要）+ fixpoint（定點疊代）追蹤橫跨多個函式的漏洞鏈（如 source 在 A 函式進入、傳給 B 函式才拼進 SQL），正確處理遞迴與互相呼叫。

同一行若多個 SQL 引擎命中，只保留資訊最完整的（inter-procedural > 單函式 taint > pattern）。

---

## 開發狀態

本專案以五個垂直切片漸進開發，五個里程碑皆已完成：

- [x] **M1** — Walking Skeleton：tree-sitter AST + Hardcoded Secret 規則 + CLI
- [x] **M2** — 資料驅動規則引擎：YAML 規則、多規則（SQL / cmd / eval）、JavaScript 支援、rich 彩色輸出
- [x] **M3** — LLM 解釋層：OpenAI-compatible 後端、可設定、優雅降級
- [x] **M4** — Taint Analysis：intra-procedural source→sink 資料流追蹤
- [x] **M5** — JSON / HTML 報告、GitHub repo URL 輸入、GitHub Actions CI

詳見 [RAVEN_project_plan.md](RAVEN_project_plan.md)。

---

## 開發

```bash
# 跑測試
.venv/bin/pytest -v
```

---

## 技術棧

- **Python 3.11+**（uv 管理環境）
- **tree-sitter** — AST 解析（Python / JavaScript）
- **PyYAML** — 規則定義
- **Click** — CLI
- **Pygments** — HTML 報告的程式碼高亮
- **OpenAI SDK** — 串接本地 LLM 後端
- **pytest** — 測試

---

*RAVEN 是一個學習導向的實驗專案，用來把 SAST 的核心概念實作清楚、可驗證。*
