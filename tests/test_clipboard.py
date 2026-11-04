"""Clipboard copies always expire, and expiring never clobbers newer content.

No test here touches the real clipboard: pyperclip and the helper process are
replaced with fakes.
"""

import io

import pyperclip
import pytest

from hecate import clipboard

SECRET = "k7#Rm2-Lq9^xWz4!pT8e"


class FakeClipboard:
    def __init__(self):
        self.text = ""

    def copy(self, text):
        self.text = text

    def paste(self):
        return self.text


@pytest.fixture
def board(monkeypatch):
    fake = FakeClipboard()
    monkeypatch.setattr(pyperclip, "copy", fake.copy)
    monkeypatch.setattr(pyperclip, "paste", fake.paste)
    return fake


@pytest.fixture
def spawned(monkeypatch):
    """Capture the helper process launch instead of starting one."""
    launches = []

    class FakePopen:
        def __init__(self, args, **kwargs):
            self.stdin = io.BytesIO()
            self.stdin.close = lambda: None  # keep the bytes readable
            launches.append((args, kwargs, self.stdin))

    monkeypatch.setattr(clipboard.subprocess, "Popen", FakePopen)
    return launches


def _handoff(launch):
    _args, _kwargs, stdin = launch
    pepper_hex, digest_hex = stdin.getvalue().decode().split()
    return bytes.fromhex(pepper_hex), bytes.fromhex(digest_hex)


def test_copy_puts_the_secret_on_the_clipboard(board, spawned):
    clipboard.copy(SECRET, clear_after=15)
    assert board.text == SECRET
    assert len(spawned) == 1


def test_helper_never_sees_the_secret(board, spawned):
    clipboard.copy(SECRET, clear_after=15)
    args, kwargs, stdin = spawned[0]
    assert args[-1] == "15"
    assert SECRET not in " ".join(args)
    assert SECRET.encode() not in stdin.getvalue()
    assert kwargs["start_new_session"] is True


@pytest.mark.parametrize("seconds", [0, -1])
def test_a_copy_without_expiry_is_refused(board, spawned, seconds):
    with pytest.raises(ValueError):
        clipboard.copy(SECRET, clear_after=seconds)
    assert board.text == ""


@pytest.mark.parametrize("error", [pyperclip.PyperclipException("no xclip"), OSError("no clip.exe")])
def test_missing_clipboard_is_reported_cleanly(monkeypatch, spawned, error):
    def broken(_text):
        raise error

    monkeypatch.setattr(pyperclip, "copy", broken)
    with pytest.raises(clipboard.ClipboardUnavailable):
        clipboard.copy(SECRET, clear_after=15)
    assert spawned == []


def test_clears_when_the_secret_is_still_there(board, spawned):
    clipboard.copy(SECRET, clear_after=15)
    assert clipboard.clear_if_unchanged(*_handoff(spawned[0]))
    assert board.text == ""


def test_leaves_anything_copied_since_alone(board, spawned):
    clipboard.copy(SECRET, clear_after=15)
    board.text = "something the user copied later"
    assert not clipboard.clear_if_unchanged(*_handoff(spawned[0]))
    assert board.text == "something the user copied later"


def test_trailing_newline_from_the_backend_still_matches(board, spawned):
    clipboard.copy(SECRET, clear_after=15)
    board.text = SECRET + "\r\n"
    assert clipboard.clear_if_unchanged(*_handoff(spawned[0]))


def test_unreadable_clipboard_does_not_raise(monkeypatch, board, spawned):
    clipboard.copy(SECRET, clear_after=15)

    def broken():
        raise RuntimeError("powershell went away")

    monkeypatch.setattr(pyperclip, "paste", broken)
    assert not clipboard.clear_if_unchanged(*_handoff(spawned[0]))


def test_helper_main_waits_then_clears(monkeypatch, board, spawned):
    clipboard.copy(SECRET, clear_after=15)
    slept = []
    monkeypatch.setattr(clipboard.time, "sleep", slept.append)
    monkeypatch.setattr(
        clipboard.sys, "stdin", io.StringIO(spawned[0][2].getvalue().decode())
    )
    clipboard._helper_main(["15"])
    assert slept == [15]
    assert board.text == ""
