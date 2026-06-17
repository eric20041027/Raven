"""M2 規則引擎：讀 YAML 規則定義，套用到 AST 上。

核心理念：
    - 規則「內容」在 YAML（找什麼節點、什麼條件）—— 資料
    - 規則「如何套用」在這裡 —— 唯一一份邏輯，所有規則共用

架構（handler 分派 / 開放封閉原則）：
    不同的 node_type 由不同的 handler 函式處理，引擎查 _HANDLERS 表分派。
    要支援新節點類型 → 新增一個 handler 並註冊，_node_matches 不用改。
"""
from dataclasses import dataclass
from pathlib import Path
import yaml
from tree_sitter import Node

from raven.parser.ast_parser import iter_nodes, node_text


@dataclass
class Finding:
    rule_id: str
    severity: str
    cwe: str
    line: int
    snippet: str
    message: str


@dataclass
class Rule:
    id: str
    name: str
    severity: str
    cwe: str
    message: str
    match: dict


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @classmethod
    def from_directory(cls, directory: str) -> "RuleEngine":
        rules = []
        for path in sorted(Path(directory).glob("*.yml")):
            data = yaml.safe_load(path.read_text())
            rules.append(Rule(
                id=data["id"],
                name=data["name"],
                severity=data["severity"],
                cwe=data["cwe"],
                message=data["message"],
                match=data["match"],
            ))
        return cls(rules)

    def scan(self, tree_root: Node, source: bytes) -> list[Finding]:
        findings: list[Finding] = []
        for node in iter_nodes(tree_root):
            for rule in self.rules:
                if _node_matches(node, rule.match, source):
                    findings.append(Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        cwe=rule.cwe,
                        line=node.start_point[0] + 1,
                        snippet=node_text(node, source),
                        message=rule.message,
                    ))
        return findings


# ═══════════════════════════════════════════════════════════
#  Handler 分派：每種 node_type 由對應的 handler 處理
# ═══════════════════════════════════════════════════════════

def _node_matches(node: Node, match: dict, source: bytes) -> bool:
    """查表分派：找到對應 node_type 的 handler，交給它判斷。"""
    if node.type != match["node_type"]:
        return False
    handler = _HANDLERS.get(match["node_type"])
    if handler is None:
        return False
    return handler(node, match, source)


def _match_assignment(node: Node, match: dict, source: bytes) -> bool:
    """處理 assignment 類規則（Hardcoded Secret 等）。"""
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return False

    if "right_type" in match and right.type != match["right_type"]:
        return False

    var_name = node_text(left, source)
    value = _string_content(right, source)

    any_of = match.get("any_of", [])
    if not any_of:
        return True

    for cond in any_of:
        names = cond.get("name_contains", [])
        if any(hint in var_name.lower() for hint in names):
            return True
        prefixes = cond.get("value_prefix", [])
        if prefixes and value.startswith(tuple(prefixes)):
            return True
        min_len = cond.get("value_min_length")
        if min_len and len(value) >= min_len:
            return True
    return False


def _match_call(node: Node, match: dict, source: bytes) -> bool:
    """處理 call 類規則（SQL Injection 等）。

    match 可能含：
        function_name: [...]      被呼叫的函式名須在清單內
        argument_has: <node_type> 參數子樹須含該類型節點（如 binary_operator）
    """
    func_name = _call_function_name(node, source)   # 取被呼叫的函式名
    args = node.child_by_field_name("arguments")     # argument_list 節點

    # ─────────────────────────────────────────────
    # TODO（你寫）：兩個條件「都」要成立才算命中（and）：
    #   1. function_name：若 match 有 "function_name"，func_name 須在該清單裡
    #   2. argument_has ：若 match 有 "argument_has"，args 子樹裡須含該類型節點
    # 提示：
    #   - allowed = match.get("function_name")  →  if allowed and func_name not in allowed: return False
    #   - want = match.get("argument_has")      →  用下面的 _subtree_has(args, want) 檢查
    #   - 兩個條件都通過 → return True
    # ─────────────────────────────────────────────
    allowed = match.get("function_name",[])
    if allowed and func_name not in allowed:
        return False
    want = match.get("argument_has")
    if want and not _subtree_has(args, want):
        return False
    return True



# 註冊表：node_type → handler。加新類型只要在這裡多一行。
_HANDLERS = {
    "assignment": _match_assignment,
    "call": _match_call,
}


# ─── 以下 helper 已幫你寫好 ───────────────────────────────

def _string_content(string_node: Node, source: bytes) -> str:
    """從 string 節點取出不含引號的內容。"""
    for child in string_node.children:
        if child.type == "string_content":
            return node_text(child, source)
    return ""


def _call_function_name(call_node: Node, source: bytes) -> str:
    """取被呼叫的函式名。
    cursor.execute(...) → 'execute'（取最後一段）
    foo(...)            → 'foo'
    """
    func = call_node.child_by_field_name("function")
    if func is None:
        return ""
    text = node_text(func, source)
    return text.split(".")[-1]   # 'cursor.execute' → 'execute'


def _subtree_has(node: Node | None, node_type: str) -> bool:
    """檢查 node 的子樹裡是否含有指定類型的節點。"""
    if node is None:
        return False
    return any(n.type == node_type for n in iter_nodes(node))
