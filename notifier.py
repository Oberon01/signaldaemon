# notifier.py — robust win11toast use with safe on_click + fallback
import platform, subprocess

_IS_WIN = platform.system().lower().startswith("win")

def _notify_windows(title: str, message: str) -> bool:
    # 1) win11toast with explicit keyword args + no-op click handler
    try:
        from win11toast import toast
        # Avoid positional args; force keywords so 'on_click' doesn't get mis-bound.
        toast(title=title, body=message, icon=None, duration="short",
              on_click=(lambda *_: None))   # never None → always callable
        return True
    except Exception as e:
        # 2) Hard fallback: MessageBox (can’t be missed)
        try:
            import ctypes
            MB_ICONINFORMATION = 0x40
            ctypes.windll.user32.MessageBoxW(0, message, title, MB_ICONINFORMATION)
            return True
        except Exception as e2:
            print(f"[NOTIFY] Fallback failed: toast err={e} / msgbox err={e2}")
            return False

def notify(title: str, message: str, duration: int = 5):
    sent = False
    if _IS_WIN:
        sent = _notify_windows(title, message)
    else:
        # non-Windows minimal fallback (won't run in your setup, but harmless)
        try:
            subprocess.run(["notify-send", title, message], check=False)
            sent = True
        except Exception:
            pass
    if not sent:
        print(f"[NOTIFY] {title}: {message} (console fallback)")
