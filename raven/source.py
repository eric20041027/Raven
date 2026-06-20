"""掃描來源解析：把使用者輸入（本地路徑或 GitHub URL）變成一個可掃的目錄。

設計重點 —— clone 來的程式碼是不可信的網路輸入，所以：
  * 只接受 http(s) URL，擋掉 ssh / git@ / file://（避免讀本機檔或誤用 SSH 金鑰）。
  * 淺層 clone（--depth 1）只抓最新一版，省時省空間。
  * clone 有超時保護，避免惡意/巨大 repo 卡死。
  * clone 進 tempfile 建的暫存目錄，用 context manager 保證離開時刪除
    （即使掃描中途出錯或 Ctrl+C）。

本地路徑則原樣回傳，且不清理（不是我們建立的，不該刪）。
"""
import contextlib
import shutil
import subprocess
import tempfile
from collections.abc import Iterator

# 合法的 clone 協定白名單。只掃公開 repo，https 就夠；擋掉 ssh/file 等。
_ALLOWED_URL_PREFIXES = ("https://", "http://")

# 看起來像 URL（而非本地路徑）的前綴。合法性由 validate_url 進一步把關。
_URL_LIKE_PREFIXES = ("https://", "http://", "ssh://", "ftp://", "file://", "git@")

# git clone 超時秒數 —— 防惡意或超大 repo 讓程式無限卡住。
_CLONE_TIMEOUT_SECONDS = 120


class InvalidSourceError(ValueError):
    """輸入的來源不是合法的掃描目標（例如不被允許的 URL 協定）。"""


def is_url(target: str) -> bool:
    """判斷輸入是 URL 還是本地路徑 —— 看前綴。

    帶 scheme 或 git@ 的一律先當 URL；合法性留給 validate_url 把關。
    """
    return target.startswith(_URL_LIKE_PREFIXES)


def validate_url(url: str) -> str:
    """驗證 URL 是允許的 clone 來源；合法則原樣回傳，否則丟 InvalidSourceError。

    只接受 http(s)。ssh / git@ / file:// / 其他協定一律拒絕，
    避免存取本機檔案系統或誤用本機 SSH 金鑰。
    """
    if not url.startswith(_ALLOWED_URL_PREFIXES):
        raise InvalidSourceError(
            f"只接受 http(s) 的 repo URL，不支援：{url}\n"
            "（git@ / ssh:// / file:// 等協定基於安全考量被擋下）"
        )
    return url


def _git_clone(url: str, dest: str) -> None:
    """淺層 clone url 到 dest。失敗或超時則丟 InvalidSourceError。

    抽成獨立函式，方便測試以 monkeypatch 取代（不真的連網）。
    """
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, dest],
            check=True,
            capture_output=True,
            timeout=_CLONE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise InvalidSourceError(
            f"clone 超時（>{_CLONE_TIMEOUT_SECONDS}s）：{url}"
        ) from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.decode("utf-8", "replace").strip() if exc.stderr else ""
        raise InvalidSourceError(f"clone 失敗：{url}\n{stderr}") from exc


@contextlib.contextmanager
def resolve_source(target: str) -> Iterator[str]:
    """把輸入來源解析成一個可掃的目錄路徑。

    * URL：驗證 → 淺層 clone 到暫存目錄 → yield 該路徑 → 離開時刪除暫存目錄。
    * 本地路徑：原樣 yield，不清理。

    用 try/finally 保證 clone 出來的暫存目錄一定被清掉，即使掃描中途出錯。
    """
    if not is_url(target):
        # 本地路徑：原樣交出，結束不刪。
        yield target
        return

    # URL：先驗證協定（非法的話在 clone 前就擋下）。
    url = validate_url(target)
    tmp_dir = tempfile.mkdtemp(prefix="raven_clone_")
    try:
        _git_clone(url, tmp_dir)
        yield tmp_dir
    finally:
        # 保證清理：忽略已不存在等狀況。
        shutil.rmtree(tmp_dir, ignore_errors=True)
