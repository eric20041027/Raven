"""階段 3：Inter-procedural Taint（跨函式污點分析）。

單函式分析（taint.py）看不到橫跨多個函式的漏洞鏈，例如：

    def get_id():      return input()                 # source 在這
    def build(uid):    return "SELECT ..." + uid       # 拼接在這
    def handler():
        raw = get_id()                                # raw 接到髒回傳
        sql = build(raw)                              # raw 傳進 build
        cursor.execute(sql)                           # sink 在這

本模組用 **function summary（函式摘要）+ fixpoint（定點疊代）** 串起跨函式
的污染傳遞：

  1. 對每個函式算一份摘要，回答兩個問題：
       - 回傳值會不會髒？（取決於哪些參數髒，或函式本身呼叫了 source）
       - 哪些參數若髒，會讓髒資料流進 sink？
  2. fixpoint：反覆重算所有摘要，每輪用上一輪的別人摘要解呼叫點，直到
     不再變化（收斂）。這樣能正確處理遞迴與互相呼叫，不會無限展開。
  3. 用收斂後的摘要找出「髒資料跨函式流進 sink」的呼叫點。

範圍：聚焦 source/sink 的跨函式傳遞；跨函式 sanitizer 暫不處理。
"""
from dataclasses import dataclass, field

from tree_sitter import Node

from raven.parser.ast_parser import iter_nodes, node_text
from raven.rules.taint import (
    TaintFinding,
    SOURCE_FUNCS,
    SINK_FUNCS,
    _call_func_name,
)


@dataclass
class FuncSummary:
    """單一函式的污染摘要。"""
    name: str
    params: list[str]
    # 函式本身呼叫了 source（如 input()）→ 回傳恆髒
    always_returns_taint: bool = False
    # 哪些參數（按 index）若髒，會讓回傳值髒
    return_tainted_by: set[int] = field(default_factory=set)
    # 哪些參數（按 index）若髒，會讓髒資料流進 sink
    sink_param_indices: set[int] = field(default_factory=set)


def analyze_interproc(tree_root: Node, source: bytes) -> list[TaintFinding]:
    """跨函式污點分析入口。回傳跨函式污染流進 sink 的漏洞。"""
    funcs = _collect_functions(tree_root, source)
    summaries = _compute_summaries(funcs, source)
    return _find_vulnerabilities(funcs, summaries, source)


def _collect_functions(tree_root: Node, source: bytes) -> dict[str, Node]:
    """收集所有頂層/巢狀函式定義，以函式名為鍵。"""
    funcs: dict[str, Node] = {}
    for node in iter_nodes(tree_root):
        if node.type == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                funcs[node_text(name_node, source)] = node
    return funcs


def _func_params(func_node: Node, source: bytes) -> list[str]:
    """取函式的參數名清單（按位置）。"""
    params_node = func_node.child_by_field_name("parameters")
    if params_node is None:
        return []
    return [
        node_text(p, source)
        for p in params_node.children
        if p.type == "identifier"
    ]


def _compute_summaries(funcs: dict[str, Node],
                       source: bytes) -> dict[str, FuncSummary]:
    """用 fixpoint 疊代算出每個函式的摘要，直到所有摘要收斂。"""
    summaries = {
        name: FuncSummary(name=name, params=_func_params(node, source))
        for name, node in funcs.items()
    }

    # 反覆重算，直到某一輪沒有任何摘要改變（達到定點）。
    changed = True
    while changed:
        changed = False
        for name, node in funcs.items():
            new_summary = _summarize_function(node, summaries[name], summaries, source)
            if _summary_differs(new_summary, summaries[name]):
                summaries[name] = new_summary
                changed = True
    return summaries


def _summary_differs(a: FuncSummary, b: FuncSummary) -> bool:
    """兩份摘要的污染資訊是否不同（用來判斷 fixpoint 是否還在變）。"""
    return (
        a.always_returns_taint != b.always_returns_taint
        or a.return_tainted_by != b.return_tainted_by
        or a.sink_param_indices != b.sink_param_indices
    )


def _summarize_function(func_node: Node, current: FuncSummary,
                        summaries: dict[str, FuncSummary],
                        source: bytes) -> FuncSummary:
    """重算單一函式的摘要：用目前已知的別人摘要解函式內的呼叫點。

    在函式內做單函式 taint，但呼叫其他函式時查對方摘要來傳播污染。
    """
    params = current.params
    summary = FuncSummary(name=current.name, params=params)

    # 追蹤函式內的髒變數集合。參數一開始視為「符號髒」—— 我們要算的是
    # 「哪些參數髒會導致什麼」，故先全部當髒跑一遍，再回推是哪個參數。
    # 這裡用較直接的做法：對每個參數，標記它的污染來源 index。
    tainted: dict[str, set[int]] = {}   # 變數 → 它的髒來自哪些參數 index
    always_tainted: set[str] = set()    # 變數 → 是否帶 source 的無條件髒

    for i, p in enumerate(params):
        tainted[p] = {i}

    body = func_node.child_by_field_name("body")
    if body is None:
        return summary

    for node in _statements(body):
        _process_statement(node, tainted, always_tainted, summary,
                            summaries, source)

    return summary


def _statements(body: Node):
    """逐一走訪函式 body 內的語句節點（含巢狀）。"""
    return iter_nodes(body)


def _process_statement(node: Node, tainted: dict[str, set[int]],
                       always_tainted: set[str], summary: FuncSummary,
                       summaries: dict[str, FuncSummary], source: bytes) -> None:
    """處理單一語句：傳播污染（賦值）、偵測 sink、判定回傳污染。"""
    if node.type == "assignment":
        _process_assignment(node, tainted, always_tainted, summaries, source)

    elif node.type == "return_statement":
        _process_return(node, tainted, always_tainted, summary, summaries, source)

    elif node.type == "call":
        _process_call_for_sink(node, tainted, always_tainted, summary,
                               summaries, source)


def _process_assignment(node: Node, tainted: dict[str, set[int]],
                        always_tainted: set[str],
                        summaries: dict[str, FuncSummary], source: bytes) -> None:
    """賦值：x = <expr>。依右邊算 x 的污染來源。"""
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return
    name = node_text(left, source)

    src_params, is_always = _expr_taint(right, tainted, always_tainted,
                                         summaries, source)
    if src_params:
        tainted[name] = set(src_params)
    else:
        tainted.pop(name, None)
    if is_always:
        always_tainted.add(name)
    else:
        always_tainted.discard(name)


def _process_return(node: Node, tainted: dict[str, set[int]],
                    always_tainted: set[str], summary: FuncSummary,
                    summaries: dict[str, FuncSummary], source: bytes) -> None:
    """return <expr>：把回傳值的污染記進摘要。"""
    expr = node.child_by_field_name("argument") or _first_expr_child(node)
    if expr is None:
        return
    src_params, is_always = _expr_taint(expr, tainted, always_tainted,
                                        summaries, source)
    summary.return_tainted_by |= src_params
    if is_always:
        summary.always_returns_taint = True


def _process_call_for_sink(node: Node, tainted: dict[str, set[int]],
                           always_tainted: set[str], summary: FuncSummary,
                           summaries: dict[str, FuncSummary],
                           source: bytes) -> None:
    """呼叫節點：若是 sink 且髒資料拼進去，記下「哪些參數髒會流進 sink」。

    也處理「呼叫別的自訂函式、把髒參數傳進對方的 sink」的跨函式情況。
    """
    func_name = _call_func_name(node, source)
    args = node.child_by_field_name("arguments")

    # 情況 A：直接 sink（execute(...)），髒資料拼進字串引數。
    if func_name in SINK_FUNCS and args is not None:
        for arg in _arg_nodes(args):
            src_params, is_always = _expr_taint(arg, tainted, always_tainted,
                                                summaries, source)
            if (src_params or is_always) and _is_concat(arg):
                summary.sink_param_indices |= src_params

    # 情況 B：呼叫別的自訂函式，對方某參數髒會流進它的 sink。
    callee = summaries.get(func_name)
    if callee is not None and args is not None:
        arg_list = _arg_nodes(args)
        for idx in callee.sink_param_indices:
            if idx < len(arg_list):
                src_params, is_always = _expr_taint(
                    arg_list[idx], tainted, always_tainted, summaries, source)
                if src_params:
                    summary.sink_param_indices |= src_params


def _expr_taint(expr: Node, tainted: dict[str, set[int]],
                always_tainted: set[str], summaries: dict[str, FuncSummary],
                source: bytes) -> tuple[set[int], bool]:
    """算一個運算式的污染：回傳 (來自哪些參數 index, 是否無條件髒)。

    無條件髒 = 運算式裡用到 source 函式，或用到 always_tainted 的變數，
    或呼叫了「回傳恆髒」的函式。
    """
    src_params: set[int] = set()
    is_always = False

    for n in iter_nodes(expr):
        if n.type == "identifier":
            ident = node_text(n, source)
            if ident in tainted:
                src_params |= tainted[ident]
            if ident in always_tainted:
                is_always = True
        elif n.type == "call":
            fname = _call_func_name(n, source)
            # 呼叫 source 函式 → 無條件髒
            if fname in SOURCE_FUNCS:
                is_always = True
            # 呼叫別的自訂函式 → 看對方回傳摘要
            callee = summaries.get(fname)
            if callee is not None:
                if callee.always_returns_taint:
                    is_always = True
                # 對方「回傳髒 iff 某參數髒」→ 看我們傳進去的引數髒不髒
                call_args = n.child_by_field_name("arguments")
                if callee.return_tainted_by and call_args is not None:
                    arg_list = _arg_nodes(call_args)
                    for idx in callee.return_tainted_by:
                        if idx < len(arg_list):
                            sp, ia = _expr_taint(arg_list[idx], tainted,
                                                 always_tainted, summaries, source)
                            src_params |= sp
                            is_always = is_always or ia

    return src_params, is_always


def _find_vulnerabilities(funcs: dict[str, Node],
                          summaries: dict[str, FuncSummary],
                          source: bytes) -> list[TaintFinding]:
    """用收斂後的摘要，找出「髒資料跨函式流進 sink」的實際呼叫點。

    entry 函式（沒被其他自訂函式呼叫的）的參數視為不可信輸入（source）；
    中繼函式的參數不另當 source，以免同一條鏈被每層重複報告。
    """
    called = _called_functions(funcs, summaries, source)
    findings: list[TaintFinding] = []
    seen_lines: set[int] = set()
    for name, node in funcs.items():
        is_entry = name not in called
        for f in _find_in_function(node, summaries[name], summaries, source, is_entry):
            if f.line not in seen_lines:   # 同一條鏈只報一次
                seen_lines.add(f.line)
                findings.append(f)
    return findings


def _called_functions(funcs: dict[str, Node],
                      summaries: dict[str, FuncSummary],
                      source: bytes) -> set[str]:
    """收集「被其他自訂函式呼叫過」的函式名集合。"""
    called: set[str] = set()
    for node in funcs.values():
        for n in iter_nodes(node):
            if n.type == "call":
                fname = _call_func_name(n, source)
                if fname in funcs:
                    called.add(fname)
    return called


def _find_in_function(func_node: Node, self_summary: FuncSummary,
                      summaries: dict[str, FuncSummary],
                      source: bytes, is_entry: bool) -> list[TaintFinding]:
    """在單一函式內，用摘要找出真正觸發 sink 的髒資料流。

    偵測階段追蹤「具體污染」—— 由 source 函式引入、或（entry 函式的）不可信
    參數帶入的髒值，沿資料流走到 sink。中繼函式的參數不當 source，以免同一
    條鏈被每層重複報。
    """
    findings: list[TaintFinding] = []

    tainted: dict[str, set[int]] = {}
    always_tainted: set[str] = set()

    # 只有 entry 函式的參數視為不可信輸入（source）。
    if is_entry:
        for i, p in enumerate(self_summary.params):
            tainted[p] = {i}
            always_tainted.add(p)

    body = func_node.child_by_field_name("body")
    if body is None:
        return findings

    for node in _statements(body):
        if node.type == "assignment":
            _process_assignment(node, tainted, always_tainted, summaries, source)
        elif node.type == "call":
            _check_sink_call(node, tainted, always_tainted, summaries,
                             source, findings)

    return findings


def _check_sink_call(node: Node, tainted: dict[str, set[int]],
                     always_tainted: set[str],
                     summaries: dict[str, FuncSummary], source: bytes,
                     findings: list[TaintFinding]) -> None:
    """檢查一個呼叫點是否觸發 sink 漏洞（直接 sink 或經被呼叫函式的 sink）。"""
    func_name = _call_func_name(node, source)
    args = node.child_by_field_name("arguments")
    if args is None:
        return
    arg_list = _arg_nodes(args)

    # 直接 sink：第一引數（SQL 字串位置）帶髒就危險。
    #   - 「拼接含髒」：髒資料在此處拼進 SQL（如 execute("..." + x)）
    #   - 「整個是髒變數」：上游函式已把髒資料組成 SQL 字串再傳進來
    #     （跨函式情況，危險拼接發生在別的函式裡）
    # 只看第一引數 → 參數化查詢 execute("...?", (x,)) 的第二引數 tuple 不誤判。
    if func_name in SINK_FUNCS and arg_list:
        first = arg_list[0]
        _, is_always = _expr_taint(first, tainted, always_tainted, summaries, source)
        if is_always and (_is_concat(first) or first.type == "identifier"):
            findings.append(_make_finding(node, source))
            return

    # 跨函式 sink：呼叫的函式有「髒參數→sink」，而我們傳進去的引數是髒的。
    callee = summaries.get(func_name)
    if callee is not None:
        for idx in callee.sink_param_indices:
            if idx < len(arg_list):
                _, is_always = _expr_taint(arg_list[idx], tainted,
                                           always_tainted, summaries, source)
                if is_always:
                    findings.append(_make_finding(node, source))
                    return


def _make_finding(node: Node, source: bytes) -> TaintFinding:
    return TaintFinding(
        rule_id="SQL-TAINT-IP-001",
        severity="HIGH",
        cwe="CWE-89",
        line=node.start_point[0] + 1,
        snippet=node_text(node, source),
        message="使用者輸入經跨函式資料流流入 SQL 查詢（inter-procedural taint）",
    )


# ── AST 小工具 ──────────────────────────────────────

def _arg_nodes(args: Node) -> list[Node]:
    """取 argument_list 內的實際引數節點（略過括號與逗號）。"""
    return [c for c in args.children if c.type not in ("(", ")", ",")]


def _is_concat(node: Node) -> bool:
    """節點子樹裡是否含字串拼接（binary_operator）—— SQL injection 的危險形狀。"""
    for n in iter_nodes(node):
        if n.type == "binary_operator":
            return True
    return False


def _first_expr_child(node: Node) -> Node | None:
    """取 return 節點後的第一個運算式子節點（return 關鍵字之後）。"""
    for c in node.children:
        if c.type not in ("return",):
            return c
    return None
