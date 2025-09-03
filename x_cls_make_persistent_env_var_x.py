from __future__ import annotations
import subprocess
import sys
from typing import Optional, Tuple, List, Dict


# Hardcoded token keys we manage via the GUI
_TOKENS: List[Tuple[str, str]] = [
    ("TESTPYPI_API_TOKEN", "TestPyPI API Token"),
    ("PYPI_API_TOKEN", "PyPI API Token"),
    ("GITHUB_TOKEN", "GitHub Token"),
]


class x_cls_make_persistent_env_var_x:
    """Persistent environment variable setter (Windows user scope).

    Provides set/get helpers used by the GUI-only main program.
    """

    def __init__(self, var: str, value: str = "", quiet: bool = False) -> None:
        self.var = var
        self.value = value
        self.quiet = quiet

    def set_user_env(self) -> bool:
        cmd = f'[Environment]::SetEnvironmentVariable("{self.var}", "{self.value}", "User")'
        result = self.run_powershell(cmd)
        return result.returncode == 0

    def get_user_env(self) -> Optional[str]:
        cmd = f'[Environment]::GetEnvironmentVariable("{self.var}", "User")'
        result = self.run_powershell(cmd)
        if result.returncode != 0:
            return None
        value = (result.stdout or "").strip()
        return value or None

    @staticmethod
    def run_powershell(command: str) -> subprocess.CompletedProcess:
        return subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)


def _open_gui_and_collect() -> Optional[Dict[str, str]]:
    """Open a small Tkinter window to collect the hardcoded token values.

    Returns a dict mapping var -> value or None if GUI unavailable / cancelled.
    """
    try:
        import tkinter as tk
    except Exception:
        return None

    root = tk.Tk()
    root.title("Set persistent tokens")
    entries: Dict[str, tk.Entry] = {}

    # Prefill with existing values if present
    prefill: Dict[str, str] = {}
    for var, _label in _TOKENS:
        cur = x_cls_make_persistent_env_var_x(var).get_user_env()
        if cur:
            prefill[var] = cur

    frame = tk.Frame(root, padx=10, pady=10)
    frame.pack(fill=tk.BOTH, expand=True)

    show_var = tk.BooleanVar(value=False)

    def toggle_show() -> None:
        ch = "" if show_var.get() else "*"
        for ent in entries.values():
            ent.config(show=ch)

    row = 0
    for var, label_text in _TOKENS:
        tk.Label(frame, text=label_text).grid(row=row, column=0, sticky=tk.W, pady=4)
        ent = tk.Entry(frame, width=50, show="*")
        ent.grid(row=row, column=1, pady=4)
        if var in prefill:
            ent.insert(0, prefill[var])
        entries[var] = ent
        row += 1

    chk = tk.Checkbutton(frame, text="Show values", variable=show_var, command=toggle_show)
    chk.grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=(6, 0))
    row += 1

    result: Dict[str, str] = {}

    def on_set() -> None:
        for var in entries:
            value = entries[var].get()
            result[var] = value
        root.destroy()

    def on_cancel() -> None:
        root.destroy()
        result.clear()

    btn_frame = tk.Frame(frame)
    btn_frame.grid(row=row, column=0, columnspan=2, pady=(10, 0))
    tk.Button(btn_frame, text="Set", command=on_set).pack(side=tk.LEFT, padx=(0, 6))
    tk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT)

    # Center window on screen
    root.update_idletasks()
    w = root.winfo_width()
    h = root.winfo_height()
    ws = root.winfo_screenwidth()
    hs = root.winfo_screenheight()
    x = (ws // 2) - (w // 2)
    y = (hs // 2) - (h // 2)
    try:
        root.geometry(f'+{x}+{y}')
    except Exception:
        pass

    root.mainloop()
    return result if result else None


if __name__ == "__main__":
    vals = _open_gui_and_collect()
    if vals is None:
        print("GUI unavailable or cancelled; aborting.")
        sys.exit(2)

    summaries = []
    ok_all = True
    for var, _label in _TOKENS:
        val = vals.get(var, "")
        if not val:
            summaries.append((var, False, "<empty>"))
            ok_all = False
            continue
        obj = x_cls_make_persistent_env_var_x(var, val)
        ok = obj.set_user_env()
        stored = obj.get_user_env()
        summaries.append((var, ok, stored))
        if not (ok and stored == val):
            ok_all = False

    print("Results:")
    for var, ok, stored in summaries:
        print(f"- {var}: set={'yes' if ok else 'no'} | stored={stored!r}")

    if not ok_all:
        print("Some values were not set correctly.")
        sys.exit(1)
    print("All values set. Open a NEW PowerShell window for changes to take effect in new shells.")
    sys.exit(0)