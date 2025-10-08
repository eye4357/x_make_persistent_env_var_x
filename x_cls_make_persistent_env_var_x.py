from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import sys as _sys
from collections.abc import Callable  # noqa: TC003
from contextlib import suppress
from types import ModuleType  # noqa: TC003
from typing import TYPE_CHECKING, TypeVar, cast

if TYPE_CHECKING:
    import tkinter as tk

    TkRoot = tk.Tk
    TkEntry = tk.Entry
    TkBooleanVar = tk.BooleanVar
    TkFrame = tk.Frame
    TkLabel = tk.Label
    TkButton = tk.Button
    TkCheckbutton = tk.Checkbutton
else:  # pragma: no cover - runtime fallback when tkinter unavailable
    _tk_fallback = object
    TkRoot = _tk_fallback
    TkEntry = _tk_fallback
    TkBooleanVar = _tk_fallback
    TkFrame = _tk_fallback
    TkLabel = _tk_fallback
    TkButton = _tk_fallback
    TkCheckbutton = _tk_fallback

_LOGGER = logging.getLogger("x_make")

_tk_runtime: ModuleType | None
try:
    import tkinter as tk
except (ImportError, OSError, RuntimeError):
    _tk_runtime = None
else:
    _tk_runtime = tk

T = TypeVar("T")


def _try_emit(*emitters: Callable[[], None]) -> None:
    for emit in emitters:
        if _safe_call(emit):
            break


def _safe_call(action: Callable[[], T]) -> bool:
    try:
        action()
    except Exception:  # noqa: BLE001
        return False
    return True


def _info(*args: object) -> None:
    msg = " ".join(str(a) for a in args)
    with suppress(Exception):
        _LOGGER.info("%s", msg)

    def _print() -> None:
        print(msg)

    def _write_stdout() -> None:
        _sys.stdout.write(f"{msg}\n")

    _try_emit(_print, _write_stdout)


def _error(*args: object) -> None:
    msg = " ".join(str(a) for a in args)
    with suppress(Exception):
        _LOGGER.error("%s", msg)

    def _print_stderr() -> None:
        print(msg, file=_sys.stderr)

    def _write_stderr() -> None:
        _sys.stderr.write(f"{msg}\n")

    def _print_fallback() -> None:
        print(msg)

    _try_emit(_print_stderr, _write_stderr, _print_fallback)


_TOKENS: list[tuple[str, str]] = [
    ("TESTPYPI_API_TOKEN", "TestPyPI API Token"),
    ("PYPI_API_TOKEN", "PyPI API Token"),
    ("GITHUB_TOKEN", "GitHub Token"),
]


class x_cls_make_persistent_env_var_x:  # noqa: N801
    """Persistent environment variable setter (Windows user scope)."""

    def __init__(
        self,
        var: str = "",
        value: str = "",
        *,
        quiet: bool = False,
        tokens: list[tuple[str, str]] | None = None,
        ctx: object | None = None,
    ) -> None:
        self.var = var
        self.value = value
        self.quiet = quiet
        self.tokens = tokens if tokens is not None else _TOKENS
        self._ctx = ctx

    def _is_verbose(self) -> bool:
        attr: object = getattr(self._ctx, "verbose", False)
        if isinstance(attr, bool):
            return attr
        return bool(attr)

    def set_user_env(self) -> bool:
        cmd = (
            "[Environment]::SetEnvironmentVariable("
            f'"{self.var}", "{self.value}", "User")'
        )
        result = self.run_powershell(cmd)
        return result.returncode == 0

    def get_user_env(self) -> str | None:
        cmd = "[Environment]::GetEnvironmentVariable(" f'"{self.var}", "User")'
        result = self.run_powershell(cmd)
        if result.returncode != 0:
            return None
        value = (result.stdout or "").strip()
        return value or None

    @staticmethod
    def run_powershell(command: str) -> subprocess.CompletedProcess[str]:
        powershell = shutil.which("powershell") or "powershell"
        return subprocess.run(  # noqa: S603
            [powershell, "-Command", command],
            check=False,
            capture_output=True,
            text=True,
        )

    def persist_current(self) -> int:
        any_changed = False
        for var, _label in self.tokens:
            if self._persist_one(var):
                any_changed = True

        if any_changed:
            if not self.quiet and self._is_verbose():
                _info(
                    "Done. Open a NEW PowerShell window for changes to take effect in "
                    "new shells."
                )
            return 0
        if not self.quiet and self._is_verbose():
            _info("No variables were persisted.")
        return 2

    def _persist_one(self, var: str) -> bool:
        val = os.environ.get(var)
        if not val:
            if not self.quiet and self._is_verbose():
                _info(f"{var}: not present in current shell; skipping")
            return False
        setter = x_cls_make_persistent_env_var_x(
            var, val, quiet=self.quiet, tokens=self.tokens, ctx=self._ctx
        )
        ok = setter.set_user_env()
        if ok:
            if not self.quiet and self._is_verbose():
                _info(
                    f"{var}: persisted to User environment (will appear in new shells)"
                )
            return True
        if not self.quiet and self._is_verbose():
            _error(f"{var}: failed to persist to User environment")
        return False

    def _apply_gui_values(
        self, values: dict[str, str]
    ) -> tuple[list[tuple[str, bool, str | None]], bool]:
        summaries: list[tuple[str, bool, str | None]] = []
        ok_all = True
        for var, _label in self.tokens:
            val = values.get(var, "")
            if not val:
                summaries.append((var, False, "<empty>"))
                ok_all = False
                continue
            obj = x_cls_make_persistent_env_var_x(
                var, val, quiet=self.quiet, tokens=self.tokens, ctx=self._ctx
            )
            ok = obj.set_user_env()
            stored = obj.get_user_env()
            summaries.append((var, ok, stored))
            if not (ok and stored == val):
                ok_all = False
        return summaries, ok_all

    def run_gui(self) -> int:
        vals = _open_gui_and_collect()
        if vals is None:
            if not self.quiet:
                _info("GUI unavailable or cancelled; aborting.")
            return 2

        summaries, ok_all = self._apply_gui_values(vals)

        if not self.quiet:
            _info("Results:")
            for var, ok, stored in summaries:
                shown = "<not set>" if stored in {None, "", "<empty>"} else "<hidden>"
                _info(f"- {var}: set={'yes' if ok else 'no'} | stored={shown}")

        if not ok_all:
            if not self.quiet:
                _info("Some values were not set correctly.")
            return 1
        if not self.quiet:
            _info(
                "All values set. Open a NEW PowerShell window for changes to take "
                "effect."
            )
        return 0


def _open_gui_and_collect() -> dict[str, str] | None:
    if _tk_runtime is None:
        return None

    prefill = _collect_prefill()
    root, _entries, _show_var, result = _build_gui_parts(_tk_runtime, prefill)
    return _run_gui_loop(root, result)


def _collect_prefill() -> dict[str, str]:
    prefill: dict[str, str] = {}
    for var, _label in _TOKENS:
        cur = x_cls_make_persistent_env_var_x(var).get_user_env()
        if cur:
            prefill[var] = cur
    return prefill


def _build_gui_parts(
    tk_mod: ModuleType, prefill: dict[str, str]
) -> tuple[TkRoot, dict[str, TkEntry], TkBooleanVar, dict[str, str]]:
    root = cast("TkRoot", tk_mod.Tk())
    root.title("Set persistent tokens")

    frame = cast("TkFrame", tk_mod.Frame(root, padx=10, pady=10))
    frame.pack(fill="both", expand=True)

    show_var = cast("TkBooleanVar", tk_mod.BooleanVar(value=False))
    entries: dict[str, TkEntry] = {}

    def toggle_show() -> None:
        ch = "" if bool(show_var.get()) else "*"
        for ent in entries.values():
            ent.config(show=ch)

    row = 0
    for var, label_text in _TOKENS:
        label = cast("TkLabel", tk_mod.Label(frame, text=label_text))
        label.grid(row=row, column=0, sticky="w", pady=4)
        ent = cast("TkEntry", tk_mod.Entry(frame, width=50, show="*"))
        if var in prefill:
            ent.insert(0, prefill[var])
        entries[var] = ent
        row += 1

    chk = cast(
        "TkCheckbutton",
        tk_mod.Checkbutton(
            frame, text="Show values", variable=show_var, command=toggle_show
        ),
    )
    chk.grid(row=row, column=0, columnspan=2, sticky="w", pady=(6, 0))
    row += 1

    result: dict[str, str] = {}

    def on_set() -> None:
        for var, ent in entries.items():
            result[var] = ent.get()
        root.destroy()

    def on_cancel() -> None:
        root.destroy()
        result.clear()

    btn_frame = cast("TkFrame", tk_mod.Frame(frame))
    btn_frame.grid(row=row, column=0, columnspan=2, pady=(10, 0))
    set_btn = cast("TkButton", tk_mod.Button(btn_frame, text="Set", command=on_set))
    set_btn.pack(side="left", padx=(0, 6))
    cancel_btn = cast(
        "TkButton", tk_mod.Button(btn_frame, text="Cancel", command=on_cancel)
    )
    cancel_btn.pack(side="left")

    return root, entries, show_var, result


def _run_gui_loop(root: TkRoot, result: dict[str, str]) -> dict[str, str] | None:
    if not _safe_call(root.update_idletasks):
        return None
    w = root.winfo_width()
    h = root.winfo_height()
    ws = root.winfo_screenwidth()
    hs = root.winfo_screenheight()
    x = (ws // 2) - (w // 2)
    y = (hs // 2) - (h // 2)
    _safe_call(lambda: root.geometry(f"+{x}+{y}"))
    if not _safe_call(root.mainloop):
        return None
    return result if result else None


if __name__ == "__main__":
    inst = x_cls_make_persistent_env_var_x()
    code = inst.run_gui()
    sys.exit(code)
