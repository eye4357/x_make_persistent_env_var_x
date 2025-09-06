from __future__ import annotations

import os
import subprocess
import sys
from typing import Any


import sys


def _info(*args: object) -> None:
    try:
        print(" ".join(str(a) for a in args), file=sys.stdout)
    except Exception:
        pass


def _error(*args: object) -> None:
    try:
        print(" ".join(str(a) for a in args), file=sys.stderr)
    except Exception:
        pass

# Hardcoded token keys we manage via the GUI
_TOKENS: list[tuple[str, str]] = [
    ("TESTPYPI_API_TOKEN", "TestPyPI API Token"),
    ("PYPI_API_TOKEN", "PyPI API Token"),
    ("GITHUB_TOKEN", "GitHub Token"),
]


class x_cls_make_persistent_env_var_x:
    """Persistent environment variable setter (Windows user scope).

    Provides set/get helpers used by the GUI-only main program.
    """

    def __init__(
        self,
        var: str = "",
        value: str = "",
        quiet: bool = False,
        tokens: list[tuple[str, str]] | None = None,
    ) -> None:
        """Create a helper instance.

        tokens defaults to the module-level `_TOKENS` if not provided.
        """
        self.var = var
        self.value = value
        self.quiet = quiet
        # tokens the instance manages
        self.tokens = tokens if tokens is not None else _TOKENS

    def set_user_env(self) -> bool:
        cmd = f'[Environment]::SetEnvironmentVariable("{self.var}", "{self.value}", "User")'
        result = self.run_powershell(cmd)
        return result.returncode == 0

    def get_user_env(self) -> str | None:
        cmd = f'[Environment]::GetEnvironmentVariable("{self.var}", "User")'
        result = self.run_powershell(cmd)
        if result.returncode != 0:
            return None
        value = (result.stdout or "").strip()
        return value or None

    @staticmethod
    def run_powershell(command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["powershell", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
        )

    def persist_current(self) -> int:
        """Persist configured tokens from current env into Windows User env.

        Returns 0 on success (any persisted), 2 if none persisted.
        """
        any_changed = False
        for var, _label in self.tokens:
            val = os.environ.get(var)
            if not val:
                if not self.quiet:
                    _info(f"{var}: not present in current shell; skipping")
                continue
            setter = x_cls_make_persistent_env_var_x(
                var, val, quiet=self.quiet, tokens=self.tokens
            )
            ok = setter.set_user_env()
            if ok:
                any_changed = True
                if not self.quiet:
                    _info(
                        f"{var}: persisted to User environment (will appear in new shells)"
                    )
            elif not self.quiet:
                _error(f"{var}: failed to persist to User environment")
        if any_changed:
            if not self.quiet:
                _info(
                    "Done. Open a NEW PowerShell window for changes to take effect in new shells."
                )
            return 0
        else:
            if not self.quiet:
                _info("No variables were persisted.")
            return 2

    def run_gui(self) -> int:
        """Run the GUI interactive flow. Return codes: 0 ok, 1 partial, 2 cancelled/error."""
        vals = _open_gui_and_collect()
        if vals is None:
            if not self.quiet:
                _info("GUI unavailable or cancelled; aborting.")
            return 2

        # summaries: list of (var, ok, stored_value) where stored_value may be None
        summaries: list[tuple[str, bool, str | None]] = []
        ok_all = True
        for var, _label in self.tokens:
            val = vals.get(var, "")
            if not val:
                summaries.append((var, False, "<empty>"))
                ok_all = False
                continue
            obj = x_cls_make_persistent_env_var_x(
                var, val, quiet=self.quiet, tokens=self.tokens
            )
            ok = obj.set_user_env()
            stored = obj.get_user_env()
            summaries.append((var, ok, stored))
            if not (ok and stored == val):
                ok_all = False

        if not self.quiet:
            _info("Results:")
            for var, ok, stored in summaries:
                if stored is None or stored in {"<empty>", ""}:
                    shown = "<not set>"
                else:
                    shown = "<hidden>"
                _info(f"- {var}: set={'yes' if ok else 'no'} | stored={shown}")

        if not ok_all:
            if not self.quiet:
                _info("Some values were not set correctly.")
            return 1
        if not self.quiet:
            _info(
                "All values set. Open a NEW PowerShell window for changes to take effect."
            )
        return 0


def _open_gui_and_collect() -> dict[str, str] | None:
    """Open a small Tkinter window to collect the hardcoded token values.

    Returns a dict mapping var -> value or None if GUI unavailable / cancelled.
    """
    try:
        import tkinter as _tk
    except Exception:
        return None

    prefill = _collect_prefill()
    root, entries, show_var, result = _build_gui_parts(_tk, prefill)
    return _run_gui_loop(root, entries, show_var, result)


def _collect_prefill() -> dict[str, str]:
    """Collect existing user-scope values for the managed tokens."""
    prefill: dict[str, str] = {}
    for var, _label in _TOKENS:
        cur = x_cls_make_persistent_env_var_x(var).get_user_env()
        if cur:
            prefill[var] = cur
    return prefill


def _build_gui_parts(
    tk_mod: Any, prefill: dict[str, str]
) -> tuple[Any, dict[str, Any], Any, dict[str, str]]:
    """Build widgets and layout; return (root, entries, show_var, result)."""
    root = tk_mod.Tk()
    root.title("Set persistent tokens")
    entries: dict[str, tk_mod.Entry] = {}

    frame = tk_mod.Frame(root, padx=10, pady=10)
    frame.pack(fill=tk_mod.BOTH, expand=True)

    show_var = tk_mod.BooleanVar(value=False)

    def toggle_show() -> None:
        ch = "" if show_var.get() else "*"
        for ent in entries.values():
            ent.config(show=ch)

    row = 0
    for var, label_text in _TOKENS:
        tk_mod.Label(frame, text=label_text).grid(
            row=row, column=0, sticky=tk_mod.W, pady=4
        )
        ent = tk_mod.Entry(frame, width=50, show="*")
        ent.grid(row=row, column=1, pady=4)
        if var in prefill:
            ent.insert(0, prefill[var])
        entries[var] = ent
        row += 1

    chk = tk_mod.Checkbutton(
        frame, text="Show values", variable=show_var, command=toggle_show
    )
    chk.grid(row=row, column=0, columnspan=2, sticky=tk_mod.W, pady=(6, 0))
    row += 1

    result: dict[str, str] = {}

    def on_set() -> None:
        for var, ent in entries.items():
            value = ent.get()
            result[var] = value
        root.destroy()

    def on_cancel() -> None:
        root.destroy()
        result.clear()

    btn_frame = tk_mod.Frame(frame)
    btn_frame.grid(row=row, column=0, columnspan=2, pady=(10, 0))
    tk_mod.Button(btn_frame, text="Set", command=on_set).pack(
        side=tk_mod.LEFT, padx=(0, 6)
    )
    tk_mod.Button(btn_frame, text="Cancel", command=on_cancel).pack(
        side=tk_mod.LEFT
    )

    return root, entries, show_var, result


def _run_gui_loop(
    root: Any, entries: dict[str, Any], show_var: Any, result: dict[str, str]
) -> dict[str, str] | None:
    """Center the window, run the Tk mainloop, and return collected results or None."""
    try:
        root.update_idletasks()
        w = root.winfo_width()
        h = root.winfo_height()
        ws = root.winfo_screenwidth()
        hs = root.winfo_screenheight()
        x = (ws // 2) - (w // 2)
        y = (hs // 2) - (h // 2)
        try:
            root.geometry(f"+{x}+{y}")
        except Exception:
            pass

        root.mainloop()
    except Exception:
        return None
    return result if result else None


if __name__ == "__main__":
    # Minimal entrypoint: instantiate and run the GUI-only flow.
    inst = x_cls_make_persistent_env_var_x()
    code = inst.run_gui()
    sys.exit(code)
