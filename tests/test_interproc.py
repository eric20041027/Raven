"""未來學習・階段 3：Inter-procedural taint（跨函式污點分析）。

用 function summary（函式摘要）+ fixpoint（定點疊代）做跨函式追蹤：
  * 回傳值污染：函式回傳是否髒（取決於哪些參數髒，或呼叫了 source）
  * 參數污染：哪些參數髒會流進 sink
  * fixpoint：反覆重算 summary 直到收斂，正確處理遞迴/互呼叫

範圍：聚焦 source/sink 的跨函式傳遞；跨函式 sanitizer 暫不處理。
"""
from raven.parser.ast_parser import AstParser
from raven.rules.interproc import analyze_interproc


def _scan(source_code: str):
    parser = AstParser("python")
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return analyze_interproc(tree.root_node, source)


# ── 核心：四函式漏洞鏈，單函式分析看不出、跨函式才抓得到 ──
def test_taint_flows_across_functions():
    code = '''def get_id():
    return input()

def build_query(uid):
    return "SELECT * WHERE id=" + uid

def handler():
    raw = get_id()
    sql = build_query(raw)
    cursor.execute(sql)
'''
    findings = _scan(code)
    assert len(findings) == 1
    assert findings[0].rule_id == "SQL-TAINT-IP-001"
    assert findings[0].line == 10   # execute(sql) 那行


# ── 回傳值污染：source 函式的回傳讓接收變數變髒 ──
def test_return_taint_propagates():
    code = '''def get_input():
    return input()

def run():
    x = get_input()
    cursor.execute("SELECT " + x)
'''
    findings = _scan(code)
    assert len(findings) == 1


# ── 參數污染：髒參數傳進函式、在裡面拼進 sink ──
def test_param_taint_into_sink():
    code = '''def do_query(q):
    cursor.execute("SELECT * WHERE x=" + q)

def handler(user_input):
    do_query(user_input)
'''
    findings = _scan(code)
    assert len(findings) == 1


# ── 反例：乾淨資料跨函式流動 → 不報 ──
def test_clean_data_across_functions_not_reported():
    code = '''def build_query(uid):
    return "SELECT * WHERE id=" + uid

def handler():
    safe = "42"
    sql = build_query(safe)
    cursor.execute(sql)
'''
    findings = _scan(code)
    assert len(findings) == 0   # safe 是常數、非 source → 全程乾淨


# ── 反例：函式回傳乾淨常數 → 接收變數不髒 ──
def test_constant_return_not_tainted():
    code = '''def get_default():
    return "guest"

def run():
    name = get_default()
    cursor.execute("SELECT " + name)
'''
    findings = _scan(code)
    assert len(findings) == 0


# ── fixpoint：遞迴函式不該讓分析無限迴圈 ──
def test_recursive_function_terminates():
    code = '''def recurse(n):
    if n > 0:
        return recurse(n - 1)
    return input()

def run():
    x = recurse(5)
    cursor.execute("SELECT " + x)
'''
    findings = _scan(code)
    # recurse 最終回傳 input()（髒）→ x 髒 → 報。重點是「不卡死」。
    assert len(findings) == 1


# ── 多層傳遞：髒資料經三層函式才到 sink ──
def test_multi_hop_taint():
    code = '''def layer3(v):
    cursor.execute("SELECT " + v)

def layer2(v):
    layer3(v)

def layer1(v):
    layer2(v)

def entry(user_input):
    layer1(user_input)
'''
    findings = _scan(code)
    assert len(findings) == 1   # user_input 經 entry→layer1→layer2→layer3→sink
