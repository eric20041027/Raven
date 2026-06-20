"""M5：GitHub repo 輸入（raven scan <url>）的測試。

涵蓋三塊：
1. 輸入判斷 —— URL vs 本地路徑（看前綴）。
2. URL 安全驗證 —— 只接受 http(s)，擋 file:// / ssh / git@。
3. resolve_source context manager —— clone 後 yield 路徑、結束保證清理。

clone 本身不真的連網：用 monkeypatch 換掉 subprocess 呼叫。
"""
import pathlib

import pytest

from raven.source import (
    InvalidSourceError,
    is_url,
    validate_url,
    resolve_source,
)


# ---------- 1. 輸入判斷：URL vs 本地路徑 ----------

@pytest.mark.parametrize("target", [
    "https://github.com/user/repo.git",
    "http://example.com/repo.git",
    "git@github.com:user/repo.git",
    "file:///etc/passwd",
])
def test_is_url_true_for_url_like_prefixes(target):
    """看前綴：帶 scheme 或 git@ 的都先當 URL（合法性由 validate 把關）。"""
    assert is_url(target) is True


@pytest.mark.parametrize("target", [
    "raven",
    "./src",
    "/Users/me/project",
    "../sibling",
    "some_file.py",
])
def test_is_url_false_for_local_paths(target):
    """沒有 URL 前綴的一律當本地路徑。"""
    assert is_url(target) is False


# ---------- 2. URL 安全驗證 ----------

@pytest.mark.parametrize("url", [
    "https://github.com/user/repo.git",
    "http://example.com/repo.git",
])
def test_validate_url_accepts_http_https(url):
    """只有 http(s) 是合法的 clone 來源。"""
    assert validate_url(url) == url


@pytest.mark.parametrize("bad", [
    "git@github.com:user/repo.git",   # ssh 簡寫
    "ssh://git@github.com/user/repo",  # 顯式 ssh
    "file:///etc/passwd",              # 本地檔案系統存取
    "ftp://example.com/repo",          # 其他協定
])
def test_validate_url_rejects_non_http(bad):
    """擋掉 ssh / file / 其他協定，避免讀本機檔案或誤用 SSH 金鑰。"""
    with pytest.raises(InvalidSourceError):
        validate_url(bad)


# ---------- 3. resolve_source context manager ----------

def test_resolve_source_local_path_yields_as_is(tmp_path):
    """本地路徑：原樣 yield，且結束後不刪（不是我們建的）。"""
    target = tmp_path / "project"
    target.mkdir()

    with resolve_source(str(target)) as resolved:
        assert pathlib.Path(resolved) == target
        assert pathlib.Path(resolved).exists()

    # 本地目錄不該被清掉
    assert target.exists()


def test_resolve_source_url_clones_and_cleans_up(monkeypatch):
    """URL：clone 到 temp、yield 該路徑，離開 with 後 temp 被刪除。"""
    cloned_into = {}

    def fake_clone(url, dest):
        # 模擬 git clone：在 dest 裡放一個檔案，記下用過的參數
        cloned_into["url"] = url
        cloned_into["dest"] = dest
        pathlib.Path(dest, "main.py").write_text("x = 1\n")

    monkeypatch.setattr("raven.source._git_clone", fake_clone)

    captured_path = None
    with resolve_source("https://github.com/user/repo.git") as resolved:
        captured_path = pathlib.Path(resolved)
        assert captured_path.exists()
        assert (captured_path / "main.py").exists()
        assert cloned_into["url"] == "https://github.com/user/repo.git"

    # 離開 with 後，temp 目錄整個被清掉
    assert not captured_path.exists()


def test_resolve_source_cleans_up_even_on_error(monkeypatch):
    """掃描過程中途出錯，temp 仍要被清掉（try/finally 保證）。"""
    def fake_clone(url, dest):
        pathlib.Path(dest, "main.py").write_text("x = 1\n")

    monkeypatch.setattr("raven.source._git_clone", fake_clone)

    captured_path = None
    with pytest.raises(RuntimeError):
        with resolve_source("https://github.com/user/repo.git") as resolved:
            captured_path = pathlib.Path(resolved)
            assert captured_path.exists()
            raise RuntimeError("掃描爆炸")

    assert not captured_path.exists()


def test_resolve_source_rejects_bad_url_before_cloning(monkeypatch):
    """非法 URL 在 clone 前就被擋下，不會呼叫到 git。"""
    called = {"clone": False}

    def fake_clone(url, dest):
        called["clone"] = True

    monkeypatch.setattr("raven.source._git_clone", fake_clone)

    with pytest.raises(InvalidSourceError):
        with resolve_source("git@github.com:user/repo.git"):
            pass

    assert called["clone"] is False
