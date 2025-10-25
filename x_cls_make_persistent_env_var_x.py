from __future__ import annotations

import argparse
import getpass
import hashlib
import importlib
import json
import logging
import os
import shutil
import subprocess
import sys as _sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import IO, TYPE_CHECKING, Protocol, TypeVar, cast

from x_make_common_x.json_contracts import validate_payload

from x_make_persistent_env_var_x.json_contracts import (
    ERROR_SCHEMA,
    INPUT_SCHEMA,
    OUTPUT_SCHEMA,
)


class _SchemaValidationError(Exception):
    message: str
    path: tuple[object, ...]
    schema_path: tuple[object, ...]


class _JsonSchemaModule(Protocol):
    ValidationError: type[_SchemaValidationError]


def _load_validation_error() -> type[_SchemaValidationError]:
    module = cast("_JsonSchemaModule", importlib.import_module("jsonschema"))
    return module.ValidationError


ValidationErrorType: type[_SchemaValidationError] = _load_validation_error()

if TYPE_CHECKING:

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
        def grid_columnconfigure(self, index: int, weight: int) -> None: ...

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

SCHEMA_VERSION = "x_make_persistent_env_var_x.run/1.0"


@dataclass(slots=True)
class TokenSpec:
    name: str
    label: str | None
    required: bool

    @property
    def display_label(self) -> str:
        return self.label or self.name


_DEFAULT_TOKEN_SPECS: tuple[TokenSpec, ...] = tuple(
    TokenSpec(name=token_name, label=token_label, required=True)
    for token_name, token_label in _DEFAULT_TOKENS
)


@dataclass(slots=True)
class _RunOutcome:
    action: str
    results: list[dict[str, object]]
    tokens_total: int
    tokens_modified: int
    tokens_skipped: int
    tokens_failed: int
    exit_code: int
    messages: list[str]
    snapshot: dict[str, object]


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _hash_value(value: str | None) -> str | None:
    if not value:
        return None
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:16]


def _should_redact(name: str) -> bool:
    upper = name.upper()
    sensitive_markers = ("TOKEN", "SECRET", "PASSWORD", "KEY", "API")
    return any(marker in upper for marker in sensitive_markers)


def _display_value(name: str, value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if _should_redact(name):
        return "<hidden>"
    return value


def _token_plural(count: int) -> str:
    return "" if count == 1 else "s"


def _format_token_message(template: str, count: int) -> str:
    return template.format(count=count, plural=_token_plural(count))


def _exit_code_for_current(tokens_modified: int, tokens_failed: int) -> int:
    if tokens_failed:
        return 1
    if tokens_modified:
        return 0
    return 2


def _exit_code_for_values(tokens_failed: int) -> int:
    return 1 if tokens_failed else 0


def _build_token_specs(raw: object) -> tuple[TokenSpec, ...]:
    if not isinstance(raw, Sequence):
        return _DEFAULT_TOKEN_SPECS
    specs: list[TokenSpec] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        name_obj = entry.get("name")
        if not isinstance(name_obj, str) or not name_obj:
            continue
        if name_obj in seen:
            continue
        label_obj = entry.get("label")
        label = label_obj if isinstance(label_obj, str) and label_obj else None
        required_obj = entry.get("required")
        required = bool(required_obj) if isinstance(required_obj, bool) else False
        specs.append(TokenSpec(name=name_obj, label=label, required=required))
        seen.add(name_obj)
    return tuple(specs) if specs else _DEFAULT_TOKEN_SPECS


def _token_tuples(specs: Sequence[TokenSpec]) -> tuple[Token, ...]:
    return tuple((spec.name, spec.display_label) for spec in specs)


def _normalize_values(raw: object) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        return {}
    return {
        key: value
        for key, value in raw.items()
        if isinstance(key, str) and isinstance(value, str) and value
    }


def _failure_payload(
    message: str,
    *,
    exit_code: int | None = None,
    details: Mapping[str, object] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {"status": "failure", "message": message}
    if exit_code is not None:
        payload["exit_code"] = exit_code
    if details:
        payload["details"] = dict(details)
    with suppress(ValidationErrorType):
        validate_payload(payload, ERROR_SCHEMA)
    return payload


class x_cls_make_persistent_env_var_x:  # noqa: N801
    """Persistent environment variable setter (Windows user scope)."""

    def __init__(
        self,
        var: str = "",
        value: str = "",
        *,
        quiet: bool = False,
        ctx: object | None = None,
        **token_options: object,
    ) -> None:
        self.var = var
        self.value = value
        self.quiet = quiet
        allowed_keys = {"tokens", "token_specs"}
        unexpected = set(token_options) - allowed_keys
        if unexpected:
            unexpected_keys = ", ".join(sorted(unexpected))
            message = f"Unexpected token option(s): {unexpected_keys}"
            raise TypeError(message)
        tokens = cast(
            "Sequence[Token] | None",
            token_options.get("tokens"),
        )
        token_specs = cast(
            "Sequence[TokenSpec] | None",
            token_options.get("token_specs"),
        )
        if token_specs is not None:
            resolved_specs = tuple(token_specs)
        elif tokens is not None:
            resolved_specs = tuple(
                TokenSpec(name=token_name, label=token_label, required=True)
                for token_name, token_label in tokens
            )
        else:
            resolved_specs = _DEFAULT_TOKEN_SPECS
        self.tokens = _token_tuples(resolved_specs)
        self._ctx = ctx
        self.token_specs = resolved_specs

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
        setter = type(self)(
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

    def apply_gui_values(
        self, values: Mapping[str, str]
    ) -> tuple[list[tuple[str, bool, str | None]], bool]:
        return self._apply_gui_values(values)

    def _apply_gui_values(
        self, values: Mapping[str, str]
    ) -> tuple[list[tuple[str, bool, str | None]], bool]:
        summaries: list[tuple[str, bool, str | None]] = []
        ok_all = True
        for var, _label in self.tokens:
            val = values.get(var, "")
            if not val:
                summaries.append((var, False, "<empty>"))
                ok_all = False
                continue
            obj = type(self)(
                var, val, quiet=self.quiet, tokens=self.tokens, ctx=self._ctx
            )
            ok = obj.set_user_env()
            stored = obj.get_user_env()
            summaries.append((var, ok, stored))
            if not (ok and stored == val):
                ok_all = False
        return summaries, ok_all

    def run_gui(self) -> int:
        values = self._collect_gui_values()
        if values is None:
            return self._abort_gui_run("No values captured; aborting.")
        if not values:
            return self._abort_gui_run("No values provided; aborting.")

        summaries, ok_all = self._apply_gui_values(values)
        self._report_gui_results(summaries)

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

    def _collect_gui_values(self) -> dict[str, str] | None:
        values = _open_gui_and_collect(self.tokens, ctx=self._ctx, quiet=self.quiet)
        if values is None or all(not val for val in values.values()):
            return _prompt_for_values(self.tokens, quiet=self.quiet)
        return values

    def _abort_gui_run(self, message: str) -> int:
        if not self.quiet:
            _info(message)
        return 2

    def _report_gui_results(
        self, summaries: Sequence[tuple[str, bool, str | None]]
    ) -> None:
        if self.quiet:
            return
        _info("Results:")
        for var, ok, stored in summaries:
            shown = "<not set>" if stored in {None, "", "<empty>"} else "<hidden>"
            _info(f"- {var}: set={'yes' if ok else 'no'} | stored={shown}")


def _open_gui_and_collect(
    tokens: Sequence[Token], *, ctx: object | None, quiet: bool
) -> dict[str, str] | None:
    if _tk_runtime is None:
        return None

    prefill = _collect_prefill(tokens, ctx=ctx, quiet=quiet)
    root, _entries, _show_var, result = _build_gui_parts(_tk_runtime, tokens, prefill)
    return _run_gui_loop(root, result)


def _prompt_for_values(
    tokens: Sequence[Token], *, quiet: bool
) -> dict[str, str] | None:
    if not quiet:
        print("GUI unavailable. Falling back to console prompts.")
        print(
            "Provide secrets for each token. Leave blank to skip and keep existing "
            "user-scoped values."
        )
    collected: dict[str, str] = {}
    capture_any = False
    for var, label in tokens:
        prompt = f"{label} ({var})?: "
        try:
            value = getpass.getpass(prompt)
        except (EOFError, KeyboardInterrupt):
            if not quiet:
                print("Aborted.")
            return None
        if value:
            collected[var] = value
            capture_any = True
    if not capture_any:
        return {}
    return collected


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
    root, frame = _create_gui_root(tk_mod)
    show_var = cast("TkBooleanVar", tk_mod.BooleanVar(value=False))
    entries, next_row = _create_token_rows(tk_mod, frame, tokens, prefill, show_var)
    result: dict[str, str] = {}
    _attach_gui_buttons(tk_mod, frame, next_row, entries, result, root)
    return root, entries, show_var, result


def _create_gui_root(tk_mod: ModuleType) -> tuple[TkRoot, TkFrame]:
    root = cast("TkRoot", tk_mod.Tk())
    root.title("Set persistent tokens")
    frame = cast("TkFrame", tk_mod.Frame(root, padx=10, pady=10))
    frame.pack(fill="both", expand=True)
    return root, frame


def _create_token_rows(
    tk_mod: ModuleType,
    frame: TkFrame,
    tokens: Sequence[Token],
    prefill: Mapping[str, str],
    show_var: TkBooleanVar,
) -> tuple[dict[str, TkEntry], int]:
    entries: dict[str, TkEntry] = {}

    def toggle_show() -> None:
        ch = "" if bool(show_var.get()) else "*"
        for ent in entries.values():
            ent.config(show=ch)

    row = 0
    for var, label_text in tokens:
        label = cast("TkLabel", tk_mod.Label(frame, text=label_text))
        label.grid(row=row, column=0, sticky="w", pady=4)
        entry = cast("TkEntry", tk_mod.Entry(frame, width=50, show="*"))
        if var in prefill:
            entry.insert(0, prefill[var])
        entries[var] = entry
        entry.grid(row=row, column=1, sticky="we", pady=4, padx=(6, 0))
        frame.grid_columnconfigure(1, weight=1)
        row += 1

    chk = cast(
        "TkCheckbutton",
        tk_mod.Checkbutton(
            frame, text="Show values", variable=show_var, command=toggle_show
        ),
    )
    chk.grid(row=row, column=0, columnspan=2, sticky="w", pady=(6, 0))
    return entries, row + 1


def _attach_gui_buttons(  # noqa: PLR0913 - GUI callback wiring requires explicit parameters
    tk_mod: ModuleType,
    frame: TkFrame,
    row: int,
    entries: Mapping[str, TkEntry],
    result: dict[str, str],
    root: TkRoot,
) -> None:
    def on_set() -> None:
        missing: list[str] = []
        staged: dict[str, str] = {}
        for var, entry in entries.items():
            val = entry.get().strip()
            if not val:
                missing.append(var)
            else:
                staged[var] = val
        if missing:
            msg = (
                "Provide values for all tokens before continuing.\nMissing: "
                + ", ".join(missing)
            )
            messagebox = getattr(tk_mod, "messagebox", None)
            if messagebox is not None:
                show_error_obj = getattr(messagebox, "showerror", None)
                typed_show_error = cast(
                    "Callable[[str, str], object] | None", show_error_obj
                )

                if typed_show_error is not None:

                    def _show_error() -> None:
                        typed_show_error("Tokens required", msg)

                    _safe_call(_show_error)
                else:
                    _error(msg)
            else:
                _error(msg)
            return
        result.update(staged)
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


def _collect_user_environment(
    token_specs: Sequence[TokenSpec],
    *,
    quiet: bool,
    ctx: object | None,
) -> dict[str, str | None]:
    snapshot: dict[str, str | None] = {}
    token_pairs = _token_tuples(token_specs)
    for spec in token_specs:
        reader = x_cls_make_persistent_env_var_x(
            spec.name,
            "",
            quiet=quiet,
            tokens=token_pairs,
            token_specs=token_specs,
            ctx=ctx,
        )
        snapshot[spec.name] = reader.get_user_env()
    return snapshot


def _persist_current_for_spec(
    spec: TokenSpec,
    token_pairs: Sequence[Token],
    token_specs: Sequence[TokenSpec],
    *,
    quiet: bool,
    ctx: object | None,
) -> tuple[dict[str, object], int, int, int]:
    session_value = os.environ.get(spec.name)
    reader = x_cls_make_persistent_env_var_x(
        spec.name,
        "",
        quiet=quiet,
        tokens=token_pairs,
        token_specs=token_specs,
        ctx=ctx,
    )
    before = reader.get_user_env()

    if not session_value:
        missing_entry = {
            "name": spec.name,
            "label": spec.display_label,
            "status": "skipped",
            "attempted": False,
            "stored": _display_value(spec.name, before),
            "stored_hash": _hash_value(before),
            "message": "variable missing from current session",
            "changed": False,
        }
        return missing_entry, 0, 1, 0

    setter = x_cls_make_persistent_env_var_x(
        spec.name,
        session_value,
        quiet=quiet,
        tokens=token_pairs,
        token_specs=token_specs,
        ctx=ctx,
    )
    ok = setter.set_user_env()
    after = setter.get_user_env()
    entry: dict[str, object] = {
        "name": spec.name,
        "label": spec.display_label,
        "attempted": True,
        "stored": _display_value(spec.name, after),
        "stored_hash": _hash_value(after),
    }
    if not ok or after != session_value:
        entry.update(
            {
                "status": "failed",
                "message": "failed to persist value",
                "changed": False,
            }
        )
        return entry, 0, 0, 1

    changed = before != after
    entry.update(
        {
            "status": "persisted" if changed else "unchanged",
            "message": "updated" if changed else "already current",
            "changed": changed,
        }
    )
    return entry, int(changed), 0, 0


def _persist_value_for_spec(  # noqa: PLR0913 - persistence flow needs explicit context parameters
    spec: TokenSpec,
    provided: str | None,
    token_pairs: Sequence[Token],
    token_specs: Sequence[TokenSpec],
    *,
    quiet: bool,
    ctx: object | None,
) -> tuple[dict[str, object], int, int, int]:
    reader = x_cls_make_persistent_env_var_x(
        spec.name,
        "",
        quiet=quiet,
        tokens=token_pairs,
        token_specs=token_specs,
        ctx=ctx,
    )
    before = reader.get_user_env()
    entry: dict[str, object] = {
        "name": spec.name,
        "label": spec.display_label,
    }

    if not provided:
        status = "failed" if spec.required else "skipped"
        message = (
            "required value missing" if status == "failed" else "no value provided"
        )
        entry.update(
            {
                "status": status,
                "attempted": False,
                "stored": _display_value(spec.name, before),
                "stored_hash": _hash_value(before),
                "message": message,
                "changed": False,
            }
        )
        modified = 0
        skipped = int(status == "skipped")
        failed = int(status == "failed")
        return entry, modified, skipped, failed

    setter = x_cls_make_persistent_env_var_x(
        spec.name,
        provided,
        quiet=quiet,
        tokens=token_pairs,
        token_specs=token_specs,
        ctx=ctx,
    )
    ok = setter.set_user_env()
    after = setter.get_user_env()
    entry.update(
        {
            "attempted": True,
            "stored": _display_value(spec.name, after),
            "stored_hash": _hash_value(after),
        }
    )
    if not ok or after != provided:
        entry.update(
            {
                "status": "failed",
                "message": "failed to persist value",
                "changed": False,
            }
        )
        return entry, 0, 0, 1

    changed = before != after
    entry.update(
        {
            "status": "persisted" if changed else "unchanged",
            "message": "updated" if changed else "already current",
            "changed": changed,
        }
    )
    return entry, int(changed), 0, 0


def _perform_persist_current(
    token_specs: Sequence[TokenSpec],
    *,
    quiet: bool,
    include_existing: bool,
    ctx: object | None,
) -> _RunOutcome:
    token_specs = tuple(token_specs)
    token_pairs = _token_tuples(token_specs)
    results: list[dict[str, object]] = []
    tokens_modified = 0
    tokens_skipped = 0
    tokens_failed = 0

    for spec in token_specs:
        entry, modified, skipped, failed = _persist_current_for_spec(
            spec,
            token_pairs,
            token_specs,
            quiet=quiet,
            ctx=ctx,
        )
        results.append(entry)
        tokens_modified += modified
        tokens_skipped += skipped
        tokens_failed += failed

    exit_code = _exit_code_for_current(tokens_modified, tokens_failed)

    messages: list[str] = []
    if tokens_modified:
        messages.append(
            _format_token_message(
                "Persisted {count} token{plural} from session", tokens_modified
            )
        )
    if tokens_skipped:
        messages.append(
            _format_token_message(
                "Skipped {count} token{plural} (missing session value)",
                tokens_skipped,
            )
        )
    if tokens_failed:
        messages.append(
            _format_token_message(
                "Failed to persist {count} token{plural}", tokens_failed
            )
        )

    snapshot_user = _collect_user_environment(token_specs, quiet=quiet, ctx=ctx)
    snapshot: dict[str, object] = {
        "user": {
            name: _display_value(name, value) for name, value in snapshot_user.items()
        }
    }
    if include_existing:
        snapshot["session"] = {
            spec.name: _display_value(spec.name, os.environ.get(spec.name))
            for spec in token_specs
        }

    return _RunOutcome(
        action="persist-current",
        results=results,
        tokens_total=len(token_specs),
        tokens_modified=tokens_modified,
        tokens_skipped=tokens_skipped,
        tokens_failed=tokens_failed,
        exit_code=exit_code,
        messages=messages,
        snapshot=snapshot,
    )


def _perform_persist_values(
    token_specs: Sequence[TokenSpec],
    values: Mapping[str, str],
    *,
    quiet: bool,
    include_existing: bool,
    ctx: object | None,
) -> _RunOutcome:
    token_specs = tuple(token_specs)
    token_pairs = _token_tuples(token_specs)
    results: list[dict[str, object]] = []
    provided_redacted = {
        name: _display_value(name, value) for name, value in values.items()
    }

    tokens_modified = 0
    tokens_skipped = 0
    tokens_failed = 0

    for spec in token_specs:
        entry, modified, skipped, failed = _persist_value_for_spec(
            spec,
            values.get(spec.name),
            token_pairs,
            token_specs,
            quiet=quiet,
            ctx=ctx,
        )
        results.append(entry)
        tokens_modified += modified
        tokens_skipped += skipped
        tokens_failed += failed

    snapshot_user = _collect_user_environment(token_specs, quiet=quiet, ctx=ctx)
    snapshot: dict[str, object] = {
        "user": {
            name: _display_value(name, value) for name, value in snapshot_user.items()
        },
        "provided": provided_redacted,
    }
    if include_existing:
        snapshot["session"] = {
            spec.name: _display_value(spec.name, os.environ.get(spec.name))
            for spec in token_specs
        }

    exit_code = _exit_code_for_values(tokens_failed)

    messages: list[str] = []
    if tokens_modified:
        messages.append(
            _format_token_message("Persisted {count} token{plural}", tokens_modified)
        )
    if tokens_skipped:
        messages.append(
            _format_token_message("Skipped {count} token{plural}", tokens_skipped)
        )
    if tokens_failed:
        messages.append(
            _format_token_message(
                "Failed to persist {count} token{plural}", tokens_failed
            )
        )

    return _RunOutcome(
        action="persist-values",
        results=results,
        tokens_total=len(token_specs),
        tokens_modified=tokens_modified,
        tokens_skipped=tokens_skipped,
        tokens_failed=tokens_failed,
        exit_code=exit_code,
        messages=messages,
        snapshot=snapshot,
    )


def _perform_inspect(
    token_specs: Sequence[TokenSpec],
    *,
    quiet: bool,
    include_existing: bool,
    ctx: object | None,
) -> _RunOutcome:
    token_specs = tuple(token_specs)
    snapshot_user = _collect_user_environment(token_specs, quiet=quiet, ctx=ctx)
    results: list[dict[str, object]] = []
    for spec in token_specs:
        stored = snapshot_user.get(spec.name)
        results.append(
            {
                "name": spec.name,
                "label": spec.display_label,
                "status": "unchanged",
                "attempted": False,
                "stored": _display_value(spec.name, stored),
                "stored_hash": _hash_value(stored),
                "message": "inspected",
                "changed": False,
            }
        )

    snapshot: dict[str, object] = {
        "user": {
            name: _display_value(name, value) for name, value in snapshot_user.items()
        }
    }
    if include_existing:
        snapshot["session"] = {
            spec.name: _display_value(spec.name, os.environ.get(spec.name))
            for spec in token_specs
        }

    messages = ["Inspection completed"]

    return _RunOutcome(
        action="inspect",
        results=results,
        tokens_total=len(token_specs),
        tokens_modified=0,
        tokens_skipped=0,
        tokens_failed=0,
        exit_code=0,
        messages=messages,
        snapshot=snapshot,
    )


def main_json(
    payload: Mapping[str, object], *, ctx: object | None = None
) -> dict[str, object]:
    try:
        validate_payload(payload, INPUT_SCHEMA)
    except ValidationErrorType as exc:
        error = exc
        return _failure_payload(
            "input payload failed validation",
            exit_code=2,
            details={
                "error": error.message,
                "path": [str(part) for part in error.path],
                "schema_path": [str(part) for part in error.schema_path],
            },
        )

    parameters_obj = payload.get("parameters", {})
    parameters = cast("Mapping[str, object]", parameters_obj)

    action_obj = parameters.get("action")
    action = cast("str", action_obj)
    quiet_obj = parameters.get("quiet", False)
    quiet = bool(quiet_obj) if not isinstance(quiet_obj, bool) else quiet_obj
    include_existing_obj = parameters.get("include_existing", False)
    include_existing = (
        bool(include_existing_obj)
        if not isinstance(include_existing_obj, bool)
        else include_existing_obj
    )
    notes_obj = parameters.get("notes")
    notes = notes_obj if isinstance(notes_obj, str) and notes_obj else None

    token_specs = _build_token_specs(parameters.get("tokens"))
    values = _normalize_values(parameters.get("values"))

    if action == "persist-current":
        outcome = _perform_persist_current(
            token_specs,
            quiet=quiet,
            include_existing=include_existing,
            ctx=ctx,
        )
    elif action == "persist-values":
        outcome = _perform_persist_values(
            token_specs,
            values,
            quiet=quiet,
            include_existing=include_existing,
            ctx=ctx,
        )
    elif action == "inspect":
        outcome = _perform_inspect(
            token_specs,
            quiet=quiet,
            include_existing=include_existing,
            ctx=ctx,
        )
    else:  # pragma: no cover - schema restricts action values
        return _failure_payload(
            "unsupported action",
            exit_code=1,
            details={"action": action},
        )

    summary: dict[str, object] = {
        "action": outcome.action,
        "tokens_total": outcome.tokens_total,
        "tokens_modified": outcome.tokens_modified,
        "tokens_skipped": outcome.tokens_skipped,
        "tokens_failed": outcome.tokens_failed,
        "exit_code": outcome.exit_code,
        "quiet": quiet,
    }
    if include_existing:
        summary["include_existing"] = True

    snapshot = dict(outcome.snapshot)
    if notes:
        snapshot.setdefault("notes", notes)

    result: dict[str, object] = {
        "status": "success",
        "schema_version": SCHEMA_VERSION,
        "generated_at": _timestamp(),
        "summary": summary,
        "results": outcome.results,
        "messages": outcome.messages,
        "environment_snapshot": snapshot,
    }

    try:
        validate_payload(result, OUTPUT_SCHEMA)
    except ValidationErrorType as exc:
        error = exc
        return _failure_payload(
            "generated output failed schema validation",
            exit_code=1,
            details={
                "error": error.message,
                "path": [str(part) for part in error.path],
                "schema_path": [str(part) for part in error.schema_path],
            },
        )

    return result


def _load_json_payload(file_path: str | None) -> Mapping[str, object]:
    def _load_stream(stream: IO[str]) -> Mapping[str, object]:
        payload_obj: object = json.load(stream)
        if not isinstance(payload_obj, Mapping):
            message = "JSON payload must be a mapping"
            raise TypeError(message)
        typed_payload = cast("Mapping[str, object]", payload_obj)
        return dict(typed_payload)

    if file_path:
        with Path(file_path).open("r", encoding="utf-8") as handle:
            return _load_stream(handle)
    return _load_stream(_sys.stdin)


def _run_json_cli(args: Sequence[str]) -> None:
    parser = argparse.ArgumentParser(
        description="x_make_persistent_env_var_x JSON runner"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Read JSON payload from stdin",
    )
    parser.add_argument(
        "--json-file",
        type=str,
        help="Path to JSON payload file",
    )
    parsed = parser.parse_args(args)

    if not (parsed.json or parsed.json_file):
        parser.error("JSON input required. Use --json for stdin or --json-file <path>.")

    payload = _load_json_payload(parsed.json_file if parsed.json_file else None)
    result = main_json(payload)
    json.dump(result, _sys.stdout, indent=2)
    _sys.stdout.write("\n")


__all__ = ["main_json", "x_cls_make_persistent_env_var_x"]


if __name__ == "__main__":
    _run_json_cli(_sys.argv[1:])
