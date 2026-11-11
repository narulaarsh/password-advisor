"""Review 2 E5: real macOS pasteboard check of vault.clipboard (run with the user's consent).

Uses the application's own copy_with_auto_clear on the real system pasteboard with
fictional secrets. The user's current clipboard text is saved in memory, never printed
or stored, and restored at the end (non-text clipboard content cannot be restored).
OS-level or third-party clipboard history cannot be inspected programmatically here.
"""
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vault import clipboard

SECRET_A = 'fictional-clipboard-secret-A-7f3c'
SECRET_B = 'fictional-clipboard-secret-B-91d2'
USER_TEXT = 'fictional-user-replacement-text'


def paste():
    return subprocess.run(['pbpaste'], capture_output=True, text=True).stdout


def copy(text):
    subprocess.run(['pbcopy'], input=text, text=True, check=True)


def pasteboard_types():
    """Pasteboard type identifiers only (no content), read through AppKit."""
    script = "ObjC.import('AppKit'); ObjC.deepUnwrap($.NSPasteboard.generalPasteboard.types).join('\\n')"
    out = subprocess.run(['osascript', '-l', 'JavaScript', '-e', script], capture_output=True, text=True).stdout
    return sorted({line.strip() for line in out.splitlines() if line.strip()})


def main(out=ROOT / 'results/review2/os_clipboard_check.json'):
    if sys.platform != 'darwin':
        raise SystemExit('This check targets the macOS pasteboard')
    original = paste()
    results = {}
    try:
        clipboard.copy_with_auto_clear(SECRET_A, auto_clear_seconds=2)
        on_copy = paste() == SECRET_A
        types_after_copy = pasteboard_types()
        time.sleep(3.0)
        after_timer = paste()
        results['secret_cleared_after_timer'] = dict(present_immediately=on_copy, cleared=after_timer != SECRET_A,
                                                    clipboard_empty_after_clear=after_timer == '',
                                                    pasteboard_types_after_copy=types_after_copy)
        clipboard.copy_with_auto_clear(SECRET_B, auto_clear_seconds=2)
        time.sleep(0.5)
        copy(USER_TEXT)
        time.sleep(3.0)
        results['user_replacement_preserved'] = paste() == USER_TEXT
        results['concealed_type_marked'] = 'org.nspasteboard.ConcealedType' in types_after_copy
    finally:
        copy(original)
        restored = paste() == original
    report = dict(platform=platform.platform(), method='vault.clipboard.copy_with_auto_clear on the real pasteboard (AppKit via osascript, marked concealed; pyperclip fallback)',
                  timer_seconds=2, results=results, user_clipboard_text_restored=restored,
                  limitations=['Clipboard history kept by the OS or third-party managers was not inspected',
                               'The concealed marker is a convention: only clipboard managers that honour it skip the item',
                               'One host and one run'])
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
