"""
tests/test_clipboard.py
-----------------------
Unit tests for clipboard integration and timed auto-clearing.
"""

import time
import pyperclip
from vault.clipboard import copy_with_auto_clear

def test_copy_with_auto_clear():
    secret = "TestClipboardSecret9988!"
    
    # Copy with short 0.5s auto-clear timeout
    success = copy_with_auto_clear(secret, auto_clear_seconds=0.5)
    assert success is True
    assert pyperclip.paste() == secret

    # Wait for background timer to trigger
    time.sleep(0.7)
    assert pyperclip.paste() == ""


def test_no_clear_if_user_copied_something_else():
    secret = "InitialSecret123!"
    copy_with_auto_clear(secret, auto_clear_seconds=0.5)
    
    # User immediately copies a different string
    pyperclip.copy("UserCopiedNewThing")

    # Wait for the initial timer to trigger
    time.sleep(0.7)
    # Clipboard should NOT be cleared because current content is different from original secret
    assert pyperclip.paste() == "UserCopiedNewThing"
    pyperclip.copy("")  # cleanup



from vault.clipboard import _mac_concealed_copy as real_concealed_copy  # captured before fixtures patch it


def test_concealed_copy_passes_secret_on_stdin_not_argv(monkeypatch):
    import vault.clipboard as vc
    calls = []

    class Result:
        returncode, stdout = 0, b"ok\n"

    monkeypatch.setattr(vc.sys, "platform", "darwin")
    monkeypatch.setattr(vc.subprocess, "run", lambda args, **kw: calls.append((args, kw)) or Result())
    assert real_concealed_copy("FictionalSecret#1") is True
    args, kwargs = calls[0]
    assert "FictionalSecret#1" not in " ".join(args)
    assert kwargs["input"] == b"FictionalSecret#1"
    assert "org.nspasteboard.ConcealedType" in args[-1]


def test_concealed_copy_falls_back_off_macos_or_on_failure(monkeypatch):
    import vault.clipboard as vc

    class Failed:
        returncode, stdout = 1, b""

    monkeypatch.setattr(vc.sys, "platform", "linux")
    assert real_concealed_copy("x") is False
    monkeypatch.setattr(vc.sys, "platform", "darwin")
    monkeypatch.setattr(vc.subprocess, "run", lambda *a, **k: Failed())
    assert real_concealed_copy("x") is False
