from parser import parse


def test_parse_add():
    tree = parse(["add", "GitHub"])
    assert tree is not None
    assert tree.type == "add"
    assert tree.site == "github"


def test_parse_invalid():
    # missing argument -> parse returns None
    assert parse(["add"]) is None
