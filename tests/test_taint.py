"""M4 Taint Analysis 測試。

核心驗證：taint analysis 比 pattern matching 準 ——
能正確區分「拼接使用者輸入」(報) vs「拼接常數」(不報)。
"""
from raven.parser.ast_parser import AstParser
from raven.rules.taint import analyze, sink_lines


def _taint(source_code: str):
    parser = AstParser("python")
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return analyze(tree.root_node, source)


def _sink_lines(source_code: str):
    parser = AstParser("python")
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return sink_lines(tree.root_node, source)


# 正例：函式參數(source) 經拼接流入 execute(sink) → 報
def test_param_flows_to_sink():
    code = '''def get_user(user_input):
    q = "SELECT * WHERE id=" + user_input
    cursor.execute(q)
'''
    findings = _taint(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SQL-TAINT-001"


# 關鍵反例：拼接的是常數、非 source → 不報（pattern matching 會誤報這個！）
def test_constant_concat_not_reported():
    code = '''def get_logs():
    q = "SELECT * WHERE level=" + "INFO"
    cursor.execute(q)
'''
    findings = _taint(code)
    assert len(findings) == 0   # 沒有 source 流入 → 安全，不報


# 反例：execute 固定字串、無污染 → 不報
def test_static_query_not_reported():
    code = '''def get_all():
    cursor.execute("SELECT * FROM users")
'''
    findings = _taint(code)
    assert len(findings) == 0


# 污點傳播：髒資料經拼接後多次賦值仍追得到
def test_taint_propagates_through_assignments():
    code = '''def handler(name):
    a = "SELECT " + name
    b = a
    cursor.execute(b)
'''
    findings = _taint(code)
    assert len(findings) == 1   # name 拼接→a(dangerous)→b→execute，污點傳播


# 關鍵反例：參數化查詢不該報（髒變數是獨立參數、不在拼接裡）
def test_parameterized_query_not_reported():
    code = '''def get_user(user_input):
    cursor.execute("SELECT * WHERE id=?", (user_input,))
'''
    findings = _taint(code)
    assert len(findings) == 0   # user_input 未拼進 SQL 字串 → 安全


# ── 階段 2：Sanitizer（清洗函式）──────────────────────

# 核心：髒資料經 sanitizer 洗白後再拼進 SQL → 不報（消除誤報）
def test_sanitized_value_not_reported():
    code = '''def get_user(user_input):
    safe = escape(user_input)
    cursor.execute("SELECT * WHERE id=" + safe)
'''
    findings = _taint(code)
    assert len(findings) == 0   # user_input 經 escape 洗白 → safe 乾淨 → 安全


# 保守立場：右邊是「sanitizer 呼叫 + 其他拼接」→ 仍報（tail 可能還有危險）
def test_sanitizer_plus_concat_still_reported():
    code = '''def get_user(user_input):
    half = escape(user_input) + user_input
    cursor.execute("SELECT * WHERE id=" + half)
'''
    findings = _taint(code)
    assert len(findings) == 1   # 右邊不是「整個就是 sanitizer 呼叫」→ 不洗白


# sanitizer 直接用在 sink 參數的拼接裡 → 不報
def test_sanitizer_inline_in_sink_not_reported():
    code = '''def get_user(user_input):
    cursor.execute("SELECT * WHERE id=" + escape(user_input))
'''
    findings = _taint(code)
    assert len(findings) == 0   # 拼進 SQL 的是 escape(user_input)，已洗白


# 對照：同樣結構但沒洗白 → 仍報（確認 sanitizer 不是把整類情況都放過）
def test_unsanitized_still_reported():
    code = '''def get_user(user_input):
    raw = str(user_input)
    cursor.execute("SELECT * WHERE id=" + raw)
'''
    findings = _taint(code)
    assert len(findings) == 1   # str() 不在 sanitizer 清單 → raw 仍髒 → 報


# 重新賦值洗白：x 本來髒，x = escape(x) 後變乾淨
def test_reassignment_with_sanitizer_clears_taint():
    code = '''def get_user(user_input):
    user_input = escape(user_input)
    cursor.execute("SELECT * WHERE id=" + user_input)
'''
    findings = _taint(code)
    assert len(findings) == 0   # 重新賦值後 user_input 已洗白


# sink_lines：回報所有 SQL sink 呼叫的行號（taint 已裁決的行）
def test_sink_lines_reports_all_sink_calls():
    code = '''def a(u):
    cursor.execute("X" + u)

def b(u):
    safe = escape(u)
    cursor.execute("Y" + safe)

def c():
    print("not a sink")
'''
    lines = _sink_lines(code)
    assert lines == {2, 6}   # 兩個 execute；print 不是 sink
