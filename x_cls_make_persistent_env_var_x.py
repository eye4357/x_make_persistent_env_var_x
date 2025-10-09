from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import sys as _sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from types import ModuleType
from typing import TYPE_CHECKING, TypeVar, cast

if TYPE_CHECKING:
    from typing import Protocol

    class _TkSupportsGrid(Protocol):
        def grid(self, *args: object, **kwargs: object) -> None: ...

    class _TkSupportsPack(Protocol):
        def pack(self, *args: object, **kwargs: object) -> None: ...

    class TkRoot(Protocol):
        def title(self, text: str) -> None: ...

        def destroy(self) -> None: ...

        def update_idletasks(self) -> None: ...

        def winfo_width(self) -> int: ...

        def winfo_height(self) -> int: ...

        def winfo_screenwidth(self) -> int: ...

        def winfo_screenheight(self) -> int: ...

        def geometry(self, geometry: str) -> None: ...

        def mainloop(self) -> None: ...

    class TkEntry(_TkSupportsGrid, Protocol):
        def config(self, **kwargs: object) -> None: ...

        def insert(self, index: int, string: str) -> None: ...

        def get(self) -> str: ...

    class TkBooleanVar(Protocol):
        def get(self) -> bool | int: ...

    class TkFrame(_TkSupportsPack, _TkSupportsGrid, Protocol):
        pass

    class TkLabel(_TkSupportsGrid, Protocol):
        pass

    class TkButton(_TkSupportsPack, Protocol):
        pass

    class TkCheckbutton(_TkSupportsGrid, Protocol):
        pass

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


Token = tuple[str, str]


_DEFAULT_TOKENS: tuple[Token, ...] = (
    ("TESTPYPI_API_TOKEN", "TestPyPI API Token"),
    ("PYPI_API_TOKEN", "PyPI API Token"),
    ("GITHUB_TOKEN", "GitHub Token"),
)


class x_cls_make_persistent_env_var_x:  # noqa: N801
    """Persistent environment variable setter (Windows user scope)."""

    def __init__(
        self,
        var: str = "",
        value: str = "",
        *,
        quiet: bool = False,
        tokens: Sequence[Token] | None = None,
        ctx: object | None = None,
    ) -> None:
        self.var = var
        self.value = value
        self.quiet = quiet
        self.tokens: tuple[Token, ...] = (
            tuple(tokens) if tokens is not None else _DEFAULT_TOKENS
        )
        self._ctx = ctx

    def _is_verbose(self) -> bool:
        attr: object = getattr(self._ctx, "verbose", False)
        if isinstance(attr, bool):
            return attr
        return bool(attr)

    def _should_report(self) -> bool:
        return not self.quiet and self._is_verbose()

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
        any_changed = any(self._persist_one(var) for var, _label in self.tokens)

        if any_changed:
            if self._should_report():
                _info(
                    "Done. Open a NEW PowerShell window for changes to take effect in "
                    "new shells."
                )
            return 0
        if self._should_report():
            _info("No variables were persisted.")
        return 2

    def _persist_one(self, var: str) -> bool:
        val = os.environ.get(var)
        if not val:
            if self._should_report():
                _info(f"{var}: not present in current shell; skipping")
            return False
        setter = x_cls_make_persistent_env_var_x(
            var, val, quiet=self.quiet, tokens=self.tokens, ctx=self._ctx
        )
        ok = setter.set_user_env()
        if ok:
            if self._should_report():
                _info(
                    f"{var}: persisted to User environment (will appear in new shells)"
                )
            return True
        if self._should_report():
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
        vals = _open_gui_and_collect(self.tokens, ctx=self._ctx, quiet=self.quiet)
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


def _open_gui_and_collect(
    tokens: Sequence[Token], *, ctx: object | None, quiet: bool
) -> dict[str, str] | None:
    if _tk_runtime is None:
        return None

    prefill = _collect_prefill(tokens, ctx=ctx, quiet=quiet)
    root, _entries, _show_var, result = _build_gui_parts(_tk_runtime, tokens, prefill)
    return _run_gui_loop(root, result)


def _collect_prefill(
    tokens: Sequence[Token], *, ctx: object | None, quiet: bool
) -> dict[str, str]:
    prefill: dict[str, str] = {}
    for var, _label in tokens:
        cur = x_cls_make_persistent_env_var_x(
            var, quiet=quiet, tokens=tokens, ctx=ctx
        ).get_user_env()
        if cur:
            prefill[var] = cur
    return prefill


def _build_gui_parts(
    tk_mod: ModuleType,
    tokens: Sequence[Token],
    prefill: Mapping[str, str],
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
    for var, label_text in tokens:
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
