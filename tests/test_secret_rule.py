"""M1 事後測試：驗證 Hardcoded Secret 規則。

pytest 會自動找到 test_ 開頭的函式並執行。
執行：.venv/bin/pytest  （或在 PyCharm 裡點函式旁的綠色三角形）
"""
from raven.parser.ast_parser import AstParser
from raven.rules.secret_rule import check, looks_like_secret_name, looks_like_secret_value


def _scan(source_code: str):
    """小工具：把一段 Python 原始碼字串跑過規則，回傳 findings。"""
    parser = AstParser()
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return check(tree.root_node, source)


# ── 測試 1：該抓到的密鑰要抓到 ──────────────────────────
def test_detects_hardcoded_secret():
    # Arrange：一段含密鑰的程式碼
    code = 'API_KEY = "sk-prod-abc123def456ghi789"'
    # Act
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"



# ── 測試 2：安全的寫法不該誤報 ──────────────────────────
def test_ignores_env_var():
    # Arrange：從環境變數讀，是安全的
    code = 'SAFE_KEY = os.environ["API_KEY"]'
    findings = _scan(code)
    assert len(findings) == 0

# ── 測試 3：普通短字串不該誤報 ──────────────────────────
def test_ignores_plain_string():
    code = 'greeting = "hello world"'
    findings = _scan(code)
    assert len(findings) == 0

# ── 測試 4：直接測判斷函式（單元測試最小單位）──────────────
def test_secret_name_detection():

    assert looks_like_secret_name("API_KEY")   is True
    assert looks_like_secret_name("password")  is True
    assert looks_like_secret_name("greeting")  is False
