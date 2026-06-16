"""M2 規則引擎：讀 YAML 規則定義，套用到 AST 上。

核心理念（資料與邏輯分離）：
    - 規則「內容」在 YAML（找什麼節點、什麼條件）—— 資料
    - 規則「如何套用」在這裡 —— 唯一一份邏輯，所有規則共用

對照 M1：secret_rule.check() 把判斷寫死在 Python；
         現在引擎讀 YAML 的 match 區塊，動態判斷 —— 加規則不用改這份 code。
"""
from dataclasses import dataclass
from pathlib import Path
import yaml
from tree_sitter import Node

from raven.parser.ast_parser import iter_nodes, node_text


@dataclass
class Finding:
    """一個漏洞命中結果（跟 M1 的 Finding 同形狀，多帶 message）。"""
    rule_id: str
    severity: str
    cwe: str
    line: int
    snippet: str
    message: str


@dataclass
class Rule:
    """一條從 YAML 載入的規則。"""
    id: str
    name: str
    severity: str
    cwe: str
    message: str
    match: dict          # YAML 的 match 區塊，原樣存著


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @classmethod
    def from_directory(cls, directory: str) -> "RuleEngine":
        """載入資料夾下所有 .yml 規則。"""
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
        """走訪 AST，對每個節點套用每條規則。"""
        findings: list[Finding] = []
        for node in iter_nodes(tree_root):
            for rule in self.rules:
                if self._node_matches(node, rule.match, source):
                    findings.append(Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        cwe=rule.cwe,
                        line=node.start_point[0] + 1,
                        snippet=node_text(node, source),
                        message=rule.message,
                    ))
        return findings

    def _node_matches(self, node: Node, match: dict, source: bytes) -> bool:
        """判斷一個節點是否符合某條規則的 match 條件。

        這是引擎的核心 —— 把 YAML 的 match 區塊「解讀」成判斷。
        目前支援的條件：node_type / right_type / any_of[name_contains|value_prefix|value_min_length]
        """
        # 條件 1：節點類型
        if node.type != match["node_type"]:
            return False

        # 這版只處理 assignment（M2 加 call 類規則時再擴充）
        right = node.child_by_field_name("right")
        left = node.child_by_field_name("left")
        if left is None or right is None:
            return False

        # 條件 2：右邊類型（結構條件）
        if "right_type" in match and right.type != match["right_type"]:
            return False

        # 取出變數名與字串內容，供 any_of 判斷
        var_name = node_text(left, source)
        value = _string_content(right, source)

        # 條件 3：any_of —— 任一子條件成立即可
        any_of = match.get("any_of", [])
        if not any_of:
            return True   # 沒有 any_of 就視為「結構符合即命中」

        for cond in any_of:
            # ─────────────────────────────────────────────
            # TODO（你寫）：每個 cond 是一個 dict，恰有一個 key。
            #   - 若 cond 有 "name_contains"：var_name 小寫後含任一關鍵字 → return True
            #   - 若 cond 有 "value_prefix" ：value 以任一前綴開頭 → return True
            #   - 若 cond 有 "value_min_length"：len(value) >= 該數字 → return True
            # 提示：用 cond.get("name_contains") 取值，None 代表這個 cond 不是這種
            # 提示：name_contains/value_prefix 的值是 list；value_min_length 是數字
            # ─────────────────────────────────────────────
            names = cond.get("name_contains", [])
            if any(hint in var_name.lower() for hint in names):
                return True
            prefixes = cond.get("value_prefix", [])
            if prefixes and value.startswith(tuple(prefixes)):
                return True
            min_len = cond.get("value_min_length")  # 取不到回 None
            if min_len and len(value) >= min_len:
                return True


        return False


def _string_content(string_node: Node, source: bytes) -> str:
    """從 string 節點取出不含引號的內容（沿用 M1 的 helper）。"""
    for child in string_node.children:
        if child.type == "string_content":
            return node_text(child, source)
    return ""
