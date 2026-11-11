"""
vault/clipboard.py
------------------
Clipboard integration with automatic timed clearing:
- Copies password/secret; on macOS the copy is marked org.nspasteboard.ConcealedType
  (falls back to pyperclip elsewhere or if that fails)
- Spawns background daemon thread to overwrite clipboard after N seconds (default 20s)
- Only clears if clipboard still holds the exact copied value
"""

import subprocess
import sys
import threading
import pyperclip
from typing import Optional

_ACTIVE_TIMER: Optional[threading.Timer] = None

# JavaScript for Automation: writes the text read from stdin to the general pasteboard
# and adds the org.nspasteboard.ConcealedType marker, which clipboard managers use to
# avoid recording passwords. The secret travels on stdin, never in argv or the environment.
_MAC_CONCEALED_COPY = """
ObjC.import('AppKit');
var data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
var text = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding);
var pb = $.NSPasteboard.generalPasteboard;
pb.clearContents;
var ok = pb.setStringForType(text, $.NSPasteboardTypeString);
pb.setStringForType($(''), $('org.nspasteboard.ConcealedType'));
ok ? 'ok' : 'failed';
"""


def _mac_concealed_copy(text: str) -> bool:
    """Copies text marked as concealed on macOS. Returns False if unavailable or failed."""
    if sys.platform != "darwin":
        return False
    try:
        result = subprocess.run(["osascript", "-l", "JavaScript", "-e", _MAC_CONCEALED_COPY],
                                input=text.encode("utf-8"), capture_output=True, timeout=5)
        return result.returncode == 0 and result.stdout.strip() == b"ok"
    except (OSError, subprocess.SubprocessError):
        return False


def _clear_clipboard_if_matches(original_text: str):
    try:
        current = pyperclip.paste()
        if current == original_text:
            pyperclip.copy("")
    except Exception:
        pass


def copy_with_auto_clear(text: str, auto_clear_seconds: int = 20) -> bool:
    """
    Copies text to OS clipboard and schedules automatic clearing after auto_clear_seconds.
    Returns True if successfully copied.
    """
    global _ACTIVE_TIMER
    try:
        if not _mac_concealed_copy(text):
            pyperclip.copy(text)
    except Exception:
        return False

    # Cancel previous timer if still pending
    if _ACTIVE_TIMER and _ACTIVE_TIMER.is_alive():
        _ACTIVE_TIMER.cancel()

    if auto_clear_seconds > 0:
        _ACTIVE_TIMER = threading.Timer(auto_clear_seconds, _clear_clipboard_if_matches, args=(text,))
        _ACTIVE_TIMER.daemon = True
        _ACTIVE_TIMER.start()

    return True


def copy_to_clipboard(text: str, timeout_seconds: int = 20) -> bool:
    """Convenience alias for copy_with_auto_clear."""
    return copy_with_auto_clear(text, auto_clear_seconds=timeout_seconds)

