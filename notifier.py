# notifier.py — minimal
import platform, subprocess

_IS_WIN = platform.system().lower().startswith("win")

def _ensure_win11toast():
    try:
        from win11toast import toast  # noqa: F401
        return True
    except Exception:
        try:
            # Mirrors your script: call "pip" directly
            subprocess.run(["pip", "install", "win11toast"],
                           check=True, capture_output=True, text=True)
            from win11toast import toast  # retry
            return True
        except Exception as e:
            print("[NOTIFY] Failed to install/import win11toast:", e)
            return False

def notify(title: str, message: str, duration: int = 5):
    if _IS_WIN and _ensure_win11toast():
        try:
            from win11toast import toast
            toast(title, message, duration)  # simple & reliable
            return
        except Exception as e:
            print(f"[NOTIFY] win11toast error: {e}")
    # Fallback (non-Windows or failure)
    print(f"[NOTIFY] {title}: {message}")
