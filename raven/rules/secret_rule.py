"""M1 第一條規則：Hardcoded Secret（寫死的密鑰）偵測。

M1 階段先「寫死」這條規則（不做 YAML —— YAGNI，延到 M2）。
偵測邏輯（你選的選項 C）：一個賦值，右邊是字串，且滿足以下任一：
    (A) 變數名看起來像密鑰（含 key/password/secret/token/api ...）
    (B) 字串值看起來像密鑰（夠長、或符合已知前綴如 sk-/ghp_ ...）

回傳 Finding 物件清單，每個代表一個命中的漏洞。

═══════════════════════════════════════════════════════════════
 你要寫的部分標了「TODO（你寫）」。其餘是我搭好的鷹架。
 提示：回去看 explore_ast.py 印出的樹——漏洞的形狀是：
     assignment
       identifier「變數名」      ← node.child_by_field_name("left")
       string「"值"」            ← node.child_by_field_name("right")
═══════════════════════════════════════════════════════════════
"""
from dataclasses import dataclass
from tree_sitter import Node

from raven.parser.ast_parser import iter_nodes, node_text


@dataclass
class Finding:
    """一個漏洞命中結果。"""
    rule_id: str
    severity: str
    cwe: str
    line: int
    snippet: str


# 變數名命中這些關鍵字 → 視為密鑰（選項 A 用）
SECRET_NAME_HINTS = ("key", "password", "passwd", "secret", "token", "api")

# 字串值符合這些特徵 → 視為密鑰（選項 B 用）
SECRET_VALUE_PREFIXES = ("sk-", "ghp_", "xox", "AKIA")
SECRET_MIN_LENGTH = 16   # 超過這長度的字串「可能」是密鑰


def looks_like_secret_name(var_name: str) -> bool:
    return any(hint in var_name.lower() for hint in SECRET_NAME_HINTS)


def looks_like_secret_value(value: str) -> bool:
    """(B) 字串值是否像密鑰。value 是「不含引號」的字串內容。
    TODO（你寫）：符合任一就回 True：
        - value 以 SECRET_VALUE_PREFIXES 任一開頭，或
        - value 的長度 >= SECRET_MIN_LENGTH
    """
    return value.startswith(SECRET_VALUE_PREFIXES) or len(value) >= SECRET_MIN_LENGTH

def check(tree_root: Node, source: bytes) -> list[Finding]:
    """走訪整棵 AST，找出所有 Hardcoded Secret。"""
    findings: list[Finding] = []

    for node in iter_nodes(tree_root):
        # 只看「賦值」節點
        if node.type != "assignment":
            continue

        left = node.child_by_field_name("left")    # 變數名節點
        right = node.child_by_field_name("right")  # 等號右邊節點
        if left is None or right is None:
            continue

        # 結構條件：右邊必須是「字串」（這樣自動排除 os.environ[...] 那種 subscript）
        if right.type != "string":
            continue

        var_name = node_text(left, source)
        # 取字串的「內容」（不含引號）：找 string_content 子節點
        value = _string_content(right, source)

        # ─────────────────────────────────────────────
        # TODO（你寫）：選項 C 的判斷
        #   if 變數名像密鑰 or 字串值像密鑰:
        #       把這個命中加進 findings（用下面的範本）
        # 範本：
        #   findings.append(Finding(
        #       rule_id="SECRET-001",
        #       severity="HIGH",
        #       cwe="CWE-798",
        #       line=node.start_point[0] + 1,   # tree-sitter 行號從 0 起算，+1
        #       snippet=node_text(node, source),
        #   ))
        # 實作：
        if looks_like_secret_name(var_name) or looks_like_secret_value(value):
            findings.append(Finding(
                rule_id="SECRET-001",
                severity="HIGH",
                cwe="CWE-798",
                line=node.start_point[0] + 1,   # tree-sitter 行號從 0 起算，+1
                snippet=node_text(node, source),
            ))
        # ─────────────────────────────────────────────

    return findings


def _string_content(string_node: Node, source: bytes) -> str:
    """從 string 節點取出「不含引號」的內容。
    （這個 helper 我幫你寫好，因為它要懂 string 節點的子結構。）
    """
    for child in string_node.children:
        if child.type == "string_content":
            return node_text(child, source)
    return ""  # 空字串或特殊情況
