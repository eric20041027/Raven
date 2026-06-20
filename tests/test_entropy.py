"""未來學習・階段 1：高熵值密鑰判斷。

Shannon entropy 量「亂度」：真密鑰（隨機字串）熵高，一般字串（URL/模型名/
prompt）熵低。用它取代被拿掉的 value_min_length，從「長度」這個爛信號換成
「亂度」這個好信號。

兩塊測試：
1. _shannon_entropy 純函式的數學正確性。
2. 規則引擎認得 value_entropy_min 這個新 any_of 條件。
"""
import math

from raven.parser.ast_parser import AstParser
from raven.rules.engine import RuleEngine, Rule, _shannon_entropy


# ---------- 1. _shannon_entropy 數學正確性 ----------

def test_entropy_of_empty_string_is_zero():
    """空字串沒有資訊，熵為 0。"""
    assert _shannon_entropy("") == 0.0


def test_entropy_of_single_repeated_char_is_zero():
    """只有一種字元完全可預測，熵為 0。"""
    assert _shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_of_uniform_two_chars():
    """兩種字元各半，熵正好是 1 bit（log2(2)）。"""
    # "abab" → a/b 各 50%，H = -(0.5·log2 0.5)·2 = 1.0
    assert _shannon_entropy("abab") == 1.0


def test_entropy_of_four_uniform_chars():
    """四種字元各 25%，熵為 2 bits（log2(4)）。"""
    assert math.isclose(_shannon_entropy("abcd"), 2.0)


def test_random_secret_has_higher_entropy_than_plain_string():
    """真密鑰（亂）的熵應高於人類可讀句子。"""
    secret = "aB3xK9mZ2pQ7vR1tL5"          # 看起來像金鑰（H≈4.17）
    plain = "the quick brown fox"          # 一般句子（H≈3.89）
    assert _shannon_entropy(secret) > _shannon_entropy(plain)


def test_repetitive_string_has_low_entropy():
    """重複度高的字串熵明顯偏低（這是熵能擋、長度擋不住的）。"""
    # "hello hello hello" 雖然有 17 字元，但重複多，H≈2.22
    repetitive = "hello hello hello"
    secret = "aB3xK9mZ2pQ7vR1tL5wN8cF4"     # H≈4.59
    assert _shannon_entropy(repetitive) < 3.0
    assert _shannon_entropy(secret) > _shannon_entropy(repetitive)


# ---------- 2. 引擎認得 value_entropy_min ----------

def _entropy_rule(threshold: float) -> Rule:
    """組一條只靠 value_entropy_min 命中的 assignment 規則（測試用）。"""
    return Rule(
        id="ENTROPY-TEST",
        name="High Entropy Value",
        severity="HIGH",
        cwe="CWE-798",
        message="疑似高熵值密鑰",
        match={
            "node_type": "assignment",
            "right_type": "string",
            "any_of": [{"value_entropy_min": threshold}],
        },
    )


def _scan(source_code: str, rule: Rule):
    engine = RuleEngine([rule])
    parser = AstParser()
    source = source_code.encode("utf-8")
    tree = parser.parse_source(source)
    return engine.scan(tree.root_node, source)


def test_engine_flags_high_entropy_value():
    """高熵值字串應被 value_entropy_min 命中。"""
    findings = _scan('token = "aB3xK9mZ2pQ7vR1tL5wN8cF4"', _entropy_rule(3.5))
    assert len(findings) == 1
    assert findings[0].rule_id == "ENTROPY-TEST"


def test_engine_ignores_low_entropy_value():
    """低熵值字串（一般可讀字串）不該被命中。"""
    findings = _scan('msg = "hello hello hello"', _entropy_rule(3.5))
    assert len(findings) == 0


def test_engine_ignores_long_but_repetitive_value():
    """長但重複度高的字串不該誤報 —— 這正是長度擋不住、熵擋得住的。

    註：熵不是萬靈丹。像 URL 這種「長且字元雜」的字串熵其實也偏高
    （H≈4.1），純靠熵閾值擋不乾淨，真實工具會再結合字元集/context。
    這裡用重複度高的低熵長字串，示範熵真正擅長的反例。
    """
    long_repetitive = 'note = "ababababababababababababab"'   # 長但 H=1.0
    findings = _scan(long_repetitive, _entropy_rule(3.5))
    assert len(findings) == 0


# ---------- 3. all_of：熵 + 長度雙條件（更穩的密鑰判斷）----------

def _entropy_and_length_rule(min_entropy: float, min_length: int) -> Rule:
    """組一條「熵夠高 且 夠長」才命中的規則（all_of：全部成立）。"""
    return Rule(
        id="ENTROPY-LEN-TEST",
        name="High Entropy Long Value",
        severity="HIGH",
        cwe="CWE-798",
        message="疑似高熵值密鑰",
        match={
            "node_type": "assignment",
            "right_type": "string",
            "all_of": [
                {"value_entropy_min": min_entropy},
                {"value_min_length": min_length},
            ],
        },
    )


def test_all_of_flags_high_entropy_and_long():
    """熵高 且 夠長 → 命中（像真密鑰）。"""
    findings = _scan(
        'token = "aB3xK9mZ2pQ7vR1tL5wN8cF4"',          # H≈4.59, len=24
        _entropy_and_length_rule(4.0, 8),
    )
    assert len(findings) == 1


def test_all_of_ignores_high_entropy_but_short():
    """熵高 但 太短 → 不命中（短亂碼多半不是密鑰）。"""
    findings = _scan(
        'x = "aB3x"',                                   # 熵不低但只有 4 字元
        _entropy_and_length_rule(1.5, 8),
    )
    assert len(findings) == 0


def test_all_of_ignores_long_but_low_entropy():
    """夠長 但 熵低 → 不命中（長而規律的可讀字串）。"""
    findings = _scan(
        'msg = "hello hello hello hello"',              # len 夠但 H 低
        _entropy_and_length_rule(4.0, 8),
    )
    assert len(findings) == 0
