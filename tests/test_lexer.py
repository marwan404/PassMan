from lexer import tokenize


def test_tokenize_basic():
    assert tokenize("  Search   Git ") == ["search", "git"]


def test_tokenize_empty():
    assert tokenize("") == []
