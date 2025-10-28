from __future__ import annotations

import argparse
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
from typing import IO, Any, Protocol, TypeVar, cast

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

_LOGGER = logging.getLogger("x_make")

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
    ("SLACK_TOKEN", "Slack API Token"),
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

    def run_gui(self) -> int:
        """Launch the Tkinter token dialog using the current token specs."""

        try:
            import tkinter as tk
            from tkinter import messagebox
        except ModuleNotFoundError as exc:  # pragma: no cover - platform quirk
            message = (
                "Tkinter is required for the environment vault dialog. "
                "Enable the Tk components for your Python installation."
            )
            raise RuntimeError(message) from exc

        prefill = _collect_prefill(self.tokens, ctx=self._ctx, quiet=self.quiet)
        exit_state: dict[str, int] = {"code": 2}

        root = tk.Tk()
        root.title("Persist Environment Tokens")
        root.geometry("460x320")
        root.resizable(False, False)

        frame = tk.Frame(root, padx=16, pady=16)
        frame.pack(fill="both", expand=True)

        entries: dict[str, Any] = {}
        for idx, spec in enumerate(self.token_specs):
            label = tk.Label(frame, text=spec.display_label)
            label.grid(row=idx, column=0, sticky="w", pady=4)

            entry = tk.Entry(frame, show="*")
            entry.grid(row=idx, column=1, sticky="ew", pady=4)
            stored_value = prefill.get(spec.name)
            if stored_value:
                entry.insert(0, stored_value)
            entries[spec.name] = entry

        frame.columnconfigure(1, weight=1)

        show_var = tk.BooleanVar(value=False)

        def _toggle_visibility() -> None:
            mask = "" if show_var.get() else "*"
            for entry in entries.values():
                entry.configure(show=mask)

        toggle = tk.Checkbutton(
            frame,
            text="Show values",
            variable=show_var,
            command=_toggle_visibility,
        )
        toggle.grid(
            row=len(self.token_specs),
            column=0,
            columnspan=2,
            sticky="w",
            pady=(8, 4),
        )

        status_var = tk.StringVar(value="")
        status_label = tk.Label(
            frame,
            textvariable=status_var,
            fg="#555",
            wraplength=400,
            justify="left",
        )
        status_label.grid(
            row=len(self.token_specs) + 1,
            column=0,
            columnspan=2,
            sticky="w",
        )

        def _show_status(message: str, *, is_error: bool = False) -> None:
            status_var.set(message)
            status_label.configure(fg="#a33" if is_error else "#555")

        def _finish(code: int) -> None:
            exit_state["code"] = code
            root.quit()

        def _apply(parameters: dict[str, object]) -> tuple[bool, int, list[str]]:
            payload = {
                "command": "x_make_persistent_env_var_x",
                "parameters": parameters,
            }
            result = main_json(payload, ctx=self._ctx)
            if result.get("status") != "success":
                message = (
                    str(result.get("message"))
                    if result.get("message")
                    else "Token persistence failed."
                )
                details = result.get("details")
                if isinstance(details, Mapping):
                    breakdown = ", ".join(
                        f"{key}: {value}" for key, value in details.items()
                    )
                    if breakdown:
                        message = f"{message}\n{breakdown}"
                messagebox.showerror("Persistence failed", message)
                return False, 2, []

            summary = result.get("summary")
            exit_code = 1
            if isinstance(summary, Mapping):
                code_obj = summary.get("exit_code")
                if isinstance(code_obj, int):
                    exit_code = code_obj
            messages: list[str] = []
            raw_messages = result.get("messages")
            if isinstance(raw_messages, Sequence):
                messages = [str(item) for item in raw_messages if item]
            return True, exit_code, messages

        def _handle_persist() -> None:
            _show_status("")

            provided: dict[str, str] = {}
            session_backfill: set[str] = set()
            missing_required: list[str] = []
            for spec in self.token_specs:
                value = entries[spec.name].get().strip()
                if value:
                    provided[spec.name] = value
                    continue
                session_value = os.environ.get(spec.name)
                if session_value:
                    session_backfill.add(spec.name)
                    continue
                if spec.required:
                    missing_required.append(spec.display_label or spec.name)

            if missing_required:
                messagebox.showwarning(
                    "Tokens required",
                    "Provide values for: " + ", ".join(missing_required),
                )
                return

            if not provided and not session_backfill:
                messagebox.showinfo(
                    "No values provided",
                    "Provide at least one token value before persisting.",
                )
                return

            aggregated_messages: list[str] = []
            had_failure = False

            if provided:
                ok, exit_code, messages = _apply(
                    {
                        "action": "persist-values",
                        "tokens": [
                            {
                                "name": spec.name,
                                "label": spec.display_label,
                                "required": spec.required,
                            }
                            for spec in self.token_specs
                            if spec.name in provided
                        ],
                        "values": provided,
                        "quiet": self.quiet,
                        "include_existing": True,
                    }
                )
                if not ok:
                    _show_status(
                        "Token persistence failed; adjust the values and try again.",
                        is_error=True,
                    )
                    return
                aggregated_messages.extend(messages)
                if exit_code != 0:
                    had_failure = True

            if not had_failure and session_backfill:
                ok, exit_code, messages = _apply(
                    {
                        "action": "persist-current",
                        "tokens": [
                            {
                                "name": spec.name,
                                "label": spec.display_label,
                                "required": spec.required,
                            }
                            for spec in self.token_specs
                            if spec.name in session_backfill
                        ],
                        "quiet": self.quiet,
                        "include_existing": True,
                    }
                )
                if not ok:
                    _show_status(
                        "Token persistence failed; adjust the values and try again.",
                        is_error=True,
                    )
                    return
                aggregated_messages.extend(messages)
                if exit_code != 0:
                    had_failure = True

            if had_failure:
                summary = aggregated_messages or [
                    "Token persistence reported an error. Adjust the values and try again.",
                ]
                _show_status("\n".join(summary), is_error=True)
                return

            success_messages = aggregated_messages or [
                "Token persistence succeeded. Open a new PowerShell window for fresh shells.",
            ]
            messagebox.showinfo("Tokens persisted", "\n".join(success_messages))
            _finish(0)

        def _handle_cancel() -> None:
            _finish(2)

        button_row = len(self.token_specs) + 2
        button_frame = tk.Frame(frame)
        button_frame.grid(
            row=button_row,
            column=0,
            columnspan=2,
            sticky="e",
            pady=(12, 0),
        )

        cancel_button = tk.Button(button_frame, text="Cancel", command=_handle_cancel)
        cancel_button.pack(side="right")

        persist_button = tk.Button(
            button_frame,
            text="Set Tokens",
            command=_handle_persist,
        )
        persist_button.pack(side="right", padx=(8, 0))
        persist_button.focus_set()

        root.protocol("WM_DELETE_WINDOW", _handle_cancel)

        try:
            root.mainloop()
        finally:
            with suppress(Exception):
                root.destroy()

        return int(exit_state["code"])

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


def _load_json_payload(file_path: str | None) -> dict[str, object]:
    def _load_stream(stream: IO[str]) -> dict[str, object]:
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


def _run_cli(args: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="x_make_persistent_env_var_x runtime dispatcher"
    )
    parser.add_argument(
        "--launch-gui",
        action="store_true",
        help="Launch the Tkinter dialog instead of processing JSON payloads.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Read JSON payload from stdin.",
    )
    parser.add_argument(
        "--json-file",
        type=str,
        help="Path to JSON payload file.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational logging when launching the GUI.",
    )
    parsed = parser.parse_args(args)

    namespace = cast("Mapping[str, object]", vars(parsed))
    launch_gui = bool(namespace.get("launch_gui", False))
    read_from_stdin = bool(namespace.get("json", False))
    json_file_value = namespace.get("json_file")
    json_file = json_file_value if isinstance(json_file_value, str) else None
    quiet = bool(namespace.get("quiet", False))

    if launch_gui and (read_from_stdin or json_file):
        parser.error("--launch-gui cannot be combined with JSON input flags.")

    if launch_gui:
        runner = x_cls_make_persistent_env_var_x("", "", quiet=quiet)
        try:
            return runner.run_gui()
        except RuntimeError as exc:  # Handles missing Tkinter dependencies.
            _error(str(exc))
            return 1

    if not (read_from_stdin or json_file):
        parser.error("JSON input required. Use --json for stdin or --json-file <path>.")

    payload = _load_json_payload(None if read_from_stdin else json_file)
    payload.setdefault("command", "x_make_persistent_env_var_x")
    result = main_json(payload)
    json.dump(result, _sys.stdout, indent=2)
    _sys.stdout.write("\n")

    if result.get("status") == "success":
        summary = result.get("summary")
        if isinstance(summary, Mapping):
            exit_code_obj = summary.get("exit_code")
            if isinstance(exit_code_obj, int):
                return exit_code_obj
        return 0

    failure_exit_obj = result.get("exit_code")
    if isinstance(failure_exit_obj, int):
        return failure_exit_obj
    return 1


__all__ = ["main_json", "x_cls_make_persistent_env_var_x"]


if __name__ == "__main__":
    _sys.exit(_run_cli(_sys.argv[1:]))
