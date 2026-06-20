"""M2 規則引擎：讀 YAML 規則定義，套用到 AST 上。

核心理念：
    - 規則「內容」在 YAML（找什麼節點、什麼條件）—— 資料
    - 規則「如何套用」在這裡 —— 唯一一份邏輯，所有規則共用

架構（handler 分派 / 開放封閉原則）：
    不同的 node_type 由不同的 handler 函式處理，引擎查 _HANDLERS 表分派。
    要支援新節點類型 → 新增一個 handler 並註冊，_node_matches 不用改。
"""
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import math
import yaml
from tree_sitter import Node

from raven.parser.ast_parser import iter_nodes, node_text


def _shannon_entropy(value: str) -> float:
    """算字串的 Shannon entropy（亂度，單位 bit/字元）。

    H = -Σ p(c)·log2 p(c)，對每個出現的字元 c。直覺：字元分布越均勻、越
    不可預測，熵越高。真密鑰（隨機字串）熵高，一般可讀字串（重複多）熵低。

    用「亂度」取代「長度」當密鑰信號 —— 長度會把 URL/模型名/prompt 都誤判，
    亂度則能區分「看起來像亂碼」與「人看得懂」的字串。
    """
    if not value:
        return 0.0
    n = len(value)
    entropy = -sum(
        (count / n) * math.log2(count / n)
        for count in Counter(value).values()
    )
    # abs 正規化掉浮點負零（單一字元時算出 -0.0），讓 0 就是乾淨的 0。
    return abs(entropy)


@dataclass
class Finding:
    rule_id: str
    severity: str
    cwe: str
    line: int
    snippet: str
    message: str
    llm_explanation: dict | None = None   # M3：LLM 產生的解釋；無 LLM 時維持 None


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

    def scan(self, tree_root: Node, source: bytes, language: str = "python") -> list[Finding]:
        """掃描 AST。language 決定用哪套節點名對應（語言抽象層）。"""
        lang = _LANGUAGES[language]   # 該語言的「概念 → 實際節點名」對應
        findings: list[Finding] = []
        for node in iter_nodes(tree_root):
            for rule in self.rules:
                if _node_matches(node, rule.match, source, lang):
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
#  語言抽象層：規則用「概念名」，引擎依語言翻成「實際節點名」
# ═══════════════════════════════════════════════════════════

# 概念名 → 各語言的實際 tree-sitter 節點名／欄位名
_LANGUAGES = {
    "python": {
        "assignment": "assignment", "call": "call", "string": "string",
        "string_content": "string_content", "concat": "binary_operator",
        "left": "left", "right": "right", "function": "function", "arguments": "arguments",
    },
    "javascript": {
        "assignment": "variable_declarator", "call": "call_expression", "string": "string",
        "string_content": "string_fragment", "concat": "binary_expression",
        "left": "name", "right": "value", "function": "function", "arguments": "arguments",
    },
}


# ═══════════════════════════════════════════════════════════
#  Handler 分派：每種 node_type 由對應的 handler 處理
# ═══════════════════════════════════════════════════════════

def _node_matches(node: Node, match: dict, source: bytes, lang: dict) -> bool:
    """查表分派：先把規則的「概念 node_type」翻成該語言的實際節點名再比對。"""
    concept = match["node_type"]               # 規則寫的概念名，如 "assignment"
    actual_type = lang[concept]                # 翻成該語言實際名，如 JS 的 "variable_declarator"
    if node.type != actual_type:
        return False
    handler = _HANDLERS.get(concept)           # handler 按「概念」分派，與語言無關
    if handler is None:
        return False
    return handler(node, match, source, lang)


def _match_assignment(node: Node, match: dict, source: bytes, lang: dict) -> bool:
    """處理 assignment 類規則（Hardcoded Secret 等）。節點名透過 lang 翻譯。"""
    left = node.child_by_field_name(lang["left"])
    right = node.child_by_field_name(lang["right"])
    if left is None or right is None:
        return False

    # right_type 也是概念名，翻成實際名再比對
    if "right_type" in match and right.type != lang[match["right_type"]]:
        return False

    var_name = node_text(left, source)
    value = _string_content(right, source, lang)

    # any_of：任一條件成立即命中；all_of：全部條件成立才命中。
    # 兩者可擇一使用；都沒給就只靠上面的結構條件（right_type 等）命中。
    any_of = match.get("any_of", [])
    if any_of and any(_cond_matches(c, var_name, value) for c in any_of):
        return True

    all_of = match.get("all_of", [])
    if all_of and all(_cond_matches(c, var_name, value) for c in all_of):
        return True

    return not any_of and not all_of


def _cond_matches(cond: dict, var_name: str, value: str) -> bool:
    """單一條件是否成立。any_of / all_of 共用這份判斷邏輯（DRY）。

    支援的條件：
      name_contains      變數名含任一關鍵字
      value_prefix       字串值符合任一已知前綴
      value_min_length   字串值長度達標（粗信號，配合 entropy 用較穩）
      value_entropy_min  字串值的 Shannon 熵達標（亂度信號）
    """
    names = cond.get("name_contains", [])
    if names and any(hint in var_name.lower() for hint in names):
        return True

    prefixes = cond.get("value_prefix", [])
    if prefixes and value.startswith(tuple(prefixes)):
        return True

    min_len = cond.get("value_min_length")
    if min_len is not None and len(value) >= min_len:
        return True

    min_entropy = cond.get("value_entropy_min")
    if min_entropy is not None and _shannon_entropy(value) >= min_entropy:
        return True

    return False


def _match_call(node: Node, match: dict, source: bytes, lang: dict) -> bool:
    """處理 call 類規則（SQL Injection 等）。

    match 可能含：
        function_name: [...]   被呼叫的函式名須在清單內
        argument_has: <概念>   參數子樹須含該概念節點（如 concat = 拼接）
    """
    func_name = _call_function_name(node, source, lang)
    args = node.child_by_field_name(lang["arguments"])

    allowed = match.get("function_name", [])
    if allowed and func_name not in allowed:
        return False
    want = match.get("argument_has")
    if want and not _subtree_has(args, lang[want]):
        return False
    return True



# 註冊表：node_type → handler。加新類型只要在這裡多一行。
_HANDLERS = {
    "assignment": _match_assignment,
    "call": _match_call,
}


# ─── 以下 helper 已幫你寫好 ───────────────────────────────

def _string_content(string_node: Node, source: bytes, lang: dict) -> str:
    """從 string 節點取出不含引號的內容（字串內容的節點名依語言不同）。"""
    target = lang["string_content"]   # python: string_content / js: string_fragment
    for child in string_node.children:
        if child.type == target:
            return node_text(child, source)
    return ""


def _call_function_name(call_node: Node, source: bytes, lang: dict) -> str:
    """取被呼叫的函式名。
    cursor.execute(...) → 'execute'（取最後一段）
    foo(...)            → 'foo'
    """
    func = call_node.child_by_field_name(lang["function"])
    if func is None:
        return ""
    text = node_text(func, source)
    return text.split(".")[-1]   # 'cursor.execute' → 'execute'


def _subtree_has(node: Node | None, node_type: str) -> bool:
    """檢查 node 的子樹裡是否含有指定類型的節點。"""
    if node is None:
        return False
    return any(n.type == node_type for n in iter_nodes(node))
