"""tree-sitter 封裝：把原始碼解析成 AST，並提供遍歷器。

這層把 tree-sitter 的 API 細節藏起來，讓上層（規則引擎）只需要：
    parser = AstParser()
    tree = parser.parse_file("foo.py")
    for node in iter_nodes(tree.root_node):
        ...  # 檢查每個節點
"""
from tree_sitter import Language, Parser, Tree, Node
import tree_sitter_python


class AstParser:
    """目前只支援 Python；M2 會擴充多語言。"""

    def __init__(self) -> None:
        self._language = Language(tree_sitter_python.language())
        self._parser = Parser(self._language)

    def parse_source(self, source: bytes) -> Tree:
        """把 bytes 原始碼解析成 AST。tree-sitter 吃 bytes，不吃 str。"""
        return self._parser.parse(source)

    def parse_file(self, path: str) -> Tree:
        """讀檔並解析。回傳整棵 AST。"""
        with open(path, "rb") as f:
            return self.parse_source(f.read())


def iter_nodes(node: Node):
    """深度優先走訪整棵樹，逐一 yield 每個節點。

    規則引擎用這個來「逛過每一個節點」，檢查哪些節點是漏洞。
    用 generator（yield）而非一次回傳整個 list —— 省記憶體，且寫法乾淨。
    """
    yield node
    for child in node.children:
        yield from iter_nodes(child)


def node_text(node: Node, source: bytes) -> str:
    """取一個節點對應的原始碼文字（str）。

    AST 節點本身只記「位置」（start_byte~end_byte），要看內容得回原始碼切出來。
    """
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace")

