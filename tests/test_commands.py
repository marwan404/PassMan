from commands import executeSearch, executeLs


def test_execute_search(capsys):
    vault = {
        "entries": [
            {"site": "github", "username": "u", "password": "p"},
            {"site": "gitlab", "username": "v", "password": "q"},
        ]
    }
    executeSearch("git", vault)
    captured = capsys.readouterr().out
    assert "1. github" in captured
    assert "2. gitlab" in captured


def test_execute_ls(capsys):
    vault = {"entries": [{"site": "github", "username": "u", "password": "p"}]}
    executeLs(vault)
    captured = capsys.readouterr().out
    assert "Website" in captured
    assert "github" in captured
