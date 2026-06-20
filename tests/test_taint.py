"""M4 Taint Analysis 測試。

核心驗證：taint analysis 比 pattern matching 準 ——
能正確區分「拼接使用者輸入」(報) vs「拼接常數」(不報)。
"""
from raven.parser.ast_parser import AstParser
from raven.rules.taint import analyze


def _taint(source_code: str):
    parser = AstParser("python")
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return analyze(tree.root_node, source)


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


# 污點傳播：髒資料經多次賦值仍追得到
def test_taint_propagates_through_assignments():
    code = '''def handler(name):
    a = name
    b = a
    cursor.execute(b)
'''
    findings = _taint(code)
    assert len(findings) == 1   # name → a → b → execute，污點一路傳播
