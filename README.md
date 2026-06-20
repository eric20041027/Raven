# RAVEN 🪶

[![CI](https://github.com/eric20041027/Raven/actions/workflows/ci.yml/badge.svg)](https://github.com/eric20041027/Raven/actions/workflows/ci.yml)

### Risk Analysis & Vulnerability Examination Node

> 本地 LLM 驅動的靜態程式碼漏洞掃描器（SAST）。輸入程式碼路徑，自動解析 AST、比對漏洞規則，並（可選）由本地 LLM 產出人話說明與修補建議——**全程離線、零雲端**。

---

## 這是什麼

RAVEN 用 [tree-sitter](https://tree-sitter.github.io/tree-sitter/) 把程式碼解析成抽象語法樹（AST），再用 YAML 定義的規則在樹上比對，找出常見的安全漏洞。可選地，它會把命中的漏洞丟給本地 LLM（透過 OpenAI-compatible API，如 Ollama 或 oMLX）產生白話風險說明與修補建議。

**設計原則：**
- **規則引擎為核心、必跑、零外部依賴**——沒有 LLM 後端也能掃出漏洞
- **LLM 為可選增強層**——後端可設定（`base_url` / `api_key` / `model`），可缺席時優雅降級
- **資料驅動規則**——新增規則 = 寫一個 YAML 檔，不用改程式碼

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

# 掃描整個資料夾（遞迴掃所有 .py）
.venv/bin/raven scan path/to/project/

# 試掃內建的範例漏洞檔
.venv/bin/raven scan tests/fixtures/
```

輸出範例：

```
RAVEN v0.1.0  🪶  Risk Analysis & Vulnerability Examination Node

掃描路徑：tests/fixtures/vuln_secret.py
掃描檔案：1 個 .py
掃描規則：1 條
────────────────────────────────────────────────────

[HIGH]  SECRET-001 (CWE-798)
  檔案：tests/fixtures/vuln_secret.py，第 4 行
  程式碼：API_KEY = "sk-prod-abc123def456ghi789"
  ⚠ 密鑰寫死於原始碼，任何能讀到程式碼的人都能取得憑證。建議改用環境變數。

────────────────────────────────────────────────────
掃描完成：發現 1 個漏洞
```

---

## 規則格式

規則定義在 `raven/rules/definitions/*.yml`，每個檔一條規則。引擎會自動載入該資料夾下所有規則。

```yaml
id: SECRET-001
name: Hardcoded Secret
severity: HIGH
cwe: CWE-798
message: 密鑰寫死於原始碼，任何能讀到程式碼的人都能取得憑證。建議改用環境變數。

match:
  node_type: assignment        # 找「賦值」AST 節點
  right_type: string           # 右邊必須是字串（排除 os.environ[...] 等安全寫法）
  any_of:                      # 以下任一成立即命中
    - name_contains: [key, password, secret, token, api]   # 變數名含關鍵字
    - value_prefix: [sk-, ghp_, xox, AKIA]                 # 字串值符合已知前綴
    - value_min_length: 16                                  # 字串夠長
```

**新增規則**：在 `definitions/` 下新增一個 `.yml` 檔即可，無需改程式碼。

---

## LLM 後端（可選）

RAVEN 的 LLM 解釋層支援任何 OpenAI-compatible 後端，後端可設定：

| 後端 | 平台 | Endpoint | 需要 API key |
|------|------|----------|-------------|
| [Ollama](https://ollama.com/) | 跨平台（推薦預設） | `http://localhost:11434/v1` | 否 |
| oMLX | macOS / Apple Silicon | `http://localhost:8000/v1` | 是 |

```bash
# Ollama 範例
ollama pull qwen2.5-coder:7b
ollama serve
```

> LLM 層為**可選增強**——沒有後端時，RAVEN 仍以純規則引擎運作。

---

## 開發狀態

本專案以五個階段漸進開發（垂直切片）：

- [x] **M1** — Walking Skeleton：tree-sitter AST + Hardcoded Secret 規則 + CLI
- [ ] **M2** — 規則引擎（進行中）：YAML 規則引擎 ✅、多規則 / JS 支援 / rich 彩色輸出（待完成）
- [ ] **M3** — LLM 解釋層（後端可設定、優雅降級）
- [ ] **M4** — Taint Analysis（資料流分析）
- [ ] **M5** — HTML / JSON 報告、GitHub repo 輸入、CI

詳見 [RAVEN_project_plan.md](RAVEN_project_plan.md)。

---

## 開發

```bash
# 跑測試
.venv/bin/pytest -v
```

目前偵測能力：

| 漏洞 | CWE | 偵測法 | 狀態 |
|------|-----|--------|------|
| Hardcoded Secret | CWE-798 | pattern matching | ✅ |
| SQL Injection | CWE-89 | pattern + taint（M4） | 規劃中 |
| Command Injection | CWE-78 | pattern | 規劃中 |
| Unsafe eval | CWE-95 | pattern | 規劃中 |

---

## 技術棧

- **Python 3.11+**（uv 管理環境）
- **tree-sitter** — AST 解析
- **PyYAML** — 規則定義
- **Click** — CLI
- **pytest** — 測試
- **OpenAI SDK**（M3）— 串接本地 LLM 後端

---

*RAVEN 是一個學習導向的專案，逐階段開發中。*
