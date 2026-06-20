"""M4 Taint Analysis（污點分析）：單函式內、由上而下追蹤資料流。

跟 pattern matching 的差別：
    pattern matching 只看「形狀」（有沒有 execute + 拼接）→ 會誤報拼接常數的情況
    taint analysis 追「資料流」（source 的髒資料有沒有真的流進 sink）→ 精準

演算法（intra-procedural，單函式內線性）：
    維護 tainted 集合（哪些變數髒了）
    1. 函式參數 + source 函式的回傳 → 污染源
    2. x = <含髒變數的運算> → x 也髒（污點傳播）
    3. sink(<含髒變數>) → 報漏洞
"""
from dataclasses import dataclass
from tree_sitter import Node

from raven.parser.ast_parser import iter_nodes, node_text


@dataclass
class TaintFinding:
    rule_id: str
    severity: str
    cwe: str
    line: int
    snippet: str
    message: str
    llm_explanation: dict | None = None


# 污染源函式（呼叫這些 → 回傳值是髒的）
SOURCE_FUNCS = {"input", "get", "recv", "read"}
# 危險匯點函式（髒資料流進這些 → 漏洞）
SINK_FUNCS = {"execute", "query", "raw", "executemany"}


def analyze(tree_root: Node, source: bytes) -> list[TaintFinding]:
    """掃描所有函式，對每個函式做單函式內的污點分析。"""
    findings: list[TaintFinding] = []
    for node in iter_nodes(tree_root):
        if node.type == "function_definition":
            findings.extend(_analyze_function(node, source))
    return findings


def _analyze_function(func_node: Node, source: bytes) -> list[TaintFinding]:
    """分析單一函式：追蹤髒變數，找出「髒資料拼進 SQL」流入 sink 的情況。

    用兩個集合區分危險程度：
      tainted     —— 髒變數（來自 source）
      dangerous   —— 髒「且已被拼進字串」的變數（帶著危險的 SQL 片段）
    只有 dangerous 流進 sink，或 sink 參數內直接拼接髒變數，才算漏洞。
    這樣參數化查詢 execute(sql, (user_input,)) 會被正確放過。
    """
    findings: list[TaintFinding] = []
    tainted: set[str] = set()
    dangerous: set[str] = set()

    # ① 函式參數都是 source（外部傳入、不可信）
    params = func_node.child_by_field_name("parameters")
    if params is not None:
        for p in params.children:
            if p.type == "identifier":
                tainted.add(node_text(p, source))

    # 由上而下逐個語句掃描函式內容
    body = func_node.child_by_field_name("body")
    if body is None:
        return findings

    for node in iter_nodes(body):
        # ② 賦值：傳播污點
        if node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                name = node_text(left, source)
                if _contains_tainted(right, source, tainted):
                    tainted.add(name)   # 右邊含髒 → 左邊也髒
                # 右邊是「含髒變數的拼接」，或本身用到 dangerous 變數
                # → 左邊帶著危險 SQL 片段
                if _is_tainted_concat(right, source, tainted) or \
                        _contains_any(right, source, dangerous):
                    dangerous.add(name)

        # ③ 呼叫 sink，且髒變數出現在「字串拼接」裡 → 報漏洞
        #    收緊條件（非「參數含髒變數」）：唯有把髒資料『拼進 SQL 字串』才危險。
        #    參數化查詢 execute(sql, (user_input,)) 的 user_input 是獨立參數、
        #    不在拼接中 → 正確放過（消除誤報）。
        if node.type == "call":
            func_name = _call_func_name(node, source)
            args = node.child_by_field_name("arguments")
            # 危險條件：sink 參數內「直接拼接髒變數」，或用到 dangerous 變數
            is_dangerous = func_name in SINK_FUNCS and (
                _is_tainted_concat(args, source, tainted)
                or _contains_any(args, source, dangerous)
            )
            if is_dangerous:
                findings.append(TaintFinding(
                    rule_id="SQL-TAINT-001",
                    severity="HIGH",
                    cwe="CWE-89",
                    line=node.start_point[0] + 1,
                    snippet=node_text(node, source),
                    message="使用者輸入經資料流流入 SQL 查詢（taint 分析確認 source→sink）",
                ))

    return findings


def _contains_tainted(node: Node | None, source: bytes, tainted: set[str]) -> bool:
    """判斷一個節點的子樹裡，是否用到任何髒變數。"""
    return _contains_any(node, source, tainted)


def _contains_any(node: Node | None, source: bytes, names: set[str]) -> bool:
    """判斷子樹裡是否用到 names 集合中的任何變數。"""
    if node is None:
        return False
    for n in iter_nodes(node):
        if n.type == "identifier" and node_text(n, source) in names:
            return True
    return False


def _is_tainted_concat(node: Node | None, source: bytes, tainted: set[str]) -> bool:
    """判斷子樹裡是否有「含髒變數的字串拼接」（binary_operator 內用到髒變數）。

    這是 SQL injection 的危險本質：把髒資料拼進 SQL 字串。
    參數化查詢的髒變數是獨立引數、不在 binary_operator 內 → 回 False。
    """
    if node is None:
        return False
    for n in iter_nodes(node):
        if n.type == "binary_operator" and _contains_tainted(n, source, tainted):
            return True
    return False


def _call_func_name(call_node: Node, source: bytes) -> str:
    """取被呼叫的函式名（取最後一段：cursor.execute → execute）。"""
    func = call_node.child_by_field_name("function")
    if func is None:
        return ""
    return node_text(func, source).split(".")[-1]
