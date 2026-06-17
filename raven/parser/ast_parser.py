"""tree-sitter 封裝：把原始碼解析成 AST，並提供遍歷器。

支援多語言（Python / JavaScript）：依語言載入對應的 grammar。
語言差異（節點名不同）不在這層處理 —— 這層只負責「解析」，
節點名的語言對應交給規則引擎（engine.py）。
"""
from tree_sitter import Language, Parser, Tree, Node
import tree_sitter_python
import tree_sitter_javascript


# 副檔名 → 語言名
_EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
}

# 語言名 → tree-sitter grammar（lazy 建立，避免重複初始化）
_LANGUAGES = {
    "python": Language(tree_sitter_python.language()),
    "javascript": Language(tree_sitter_javascript.language()),
}


def detect_language(path: str) -> str | None:
    """依副檔名偵測語言；不支援的副檔名回 None。"""
    import pathlib
    return _EXT_TO_LANG.get(pathlib.Path(path).suffix)


class AstParser:
    """依語言解析原始碼成 AST。"""

    def __init__(self, language: str = "python") -> None:
        if language not in _LANGUAGES:
            raise ValueError(f"不支援的語言：{language}")
        self.language = language
        self._parser = Parser(_LANGUAGES[language])

    def parse_source(self, source: bytes) -> Tree:
        """把 bytes 原始碼解析成 AST。tree-sitter 吃 bytes，不吃 str。"""
        return self._parser.parse(source)

    def parse_file(self, path: str) -> Tree:
        """讀檔並解析。回傳整棵 AST。"""
        with open(path, "rb") as f:
            return self.parse_source(f.read())


def iter_nodes(node: Node):
    """深度優先走訪整棵樹，逐一 yield 每個節點。"""
    yield node
    for child in node.children:
        yield from iter_nodes(child)


def node_text(node: Node, source: bytes) -> str:
    """取一個節點對應的原始碼文字（str）。"""
    return source[node.start_byte:node.end_byte].decode("utf-8", "replace")
