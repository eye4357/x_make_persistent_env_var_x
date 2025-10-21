from __future__ import annotations

import os
import subprocess
from contextlib import contextmanager
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence

from x_make_persistent_env_var_x import (
    x_cls_make_persistent_env_var_x as module,
)

x_cls_make_persistent_env_var_x = module.x_cls_make_persistent_env_var_x


class TryEmit(Protocol):
    def __call__(self, *emitters: Callable[[], None]) -> None: ...


class OpenGuiHook(Protocol):
    def __call__(
        self,
        tokens: Sequence[tuple[str, str]],
        *,
        ctx: object | None,
        quiet: bool,
    ) -> dict[str, str] | None: ...


class ExpectationFailedError(AssertionError):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class ExpectationMismatchError(AssertionError):
    def __init__(self, label: str, expected: object, actual: object) -> None:
        super().__init__(f"{label}: expected {expected!r}, got {actual!r}")


MISSING_EXIT_CODE = 2


def expect(condition: object, message: str) -> None:
    if not bool(condition):
        raise ExpectationFailedError(message)


def expect_equal(actual: object, expected: object, *, label: str) -> None:
    if actual != expected:
        raise ExpectationMismatchError(label, expected, actual)


def test_safe_call_and_try_emit() -> None:
    calls: list[str] = []

    def raise_error() -> None:
        error_message = "boom"
        raise RuntimeError(error_message)

    def record_success() -> None:
        calls.append("success")

    def should_not_run() -> None:
        calls.append("unreachable")

    safe_call_attr = "_safe_call"
    try_emit_attr = "_try_emit"

    safe_call = cast(
        "Callable[[Callable[[], None]], bool]",
        getattr(module, safe_call_attr),
    )
    try_emit = cast("TryEmit", getattr(module, try_emit_attr))

    expect(
        not safe_call(raise_error),
        "safe_call should return False on exceptions",
    )
    expect(safe_call(record_success), "safe_call should return True on success")
    expect_equal(calls, ["success"], label="calls after safe_call")

    calls.clear()
    try_emit(raise_error, record_success, should_not_run)
    expect_equal(calls, ["success"], label="calls after try_emit")


def test_persist_current_sets_present_variables() -> None:
    state: dict[str, str] = {}
    tokens: list[tuple[str, str]] = [("FOO", "Foo token")]

    def fake_run(command: str) -> subprocess.CompletedProcess[str]:
        parts = command.split('"')
        if "SetEnvironmentVariable" in command:
            state[parts[1]] = parts[3]
            return subprocess.CompletedProcess(
                ["powershell", "-Command", command],
                returncode=0,
                stdout="",
                stderr="",
            )
        if "GetEnvironmentVariable" in command:
            value = state.get(parts[1], "")
            return subprocess.CompletedProcess(
                ["powershell", "-Command", command],
                returncode=0,
                stdout=value,
                stderr="",
            )
        unexpected_command = f"Unexpected command: {command}"
        raise AssertionError(unexpected_command)

    class Harness(x_cls_make_persistent_env_var_x):
        @staticmethod
        def run_powershell(command: str) -> subprocess.CompletedProcess[str]:
            return fake_run(command)

    with override_environ({"FOO": "secret"}):
        inst = Harness(tokens=tokens, quiet=True)
        exit_code = inst.persist_current()

    expect(exit_code == 0, "persist_current should succeed for present variable")
    expect_equal(state.get("FOO"), "secret", label="persisted FOO value")


def test_persist_current_skips_missing_variables() -> None:
    tokens: list[tuple[str, str]] = [("FOO", "Foo token")]

    class Harness(x_cls_make_persistent_env_var_x):
        @staticmethod
        def run_powershell(command: str) -> subprocess.CompletedProcess[str]:
            raise AssertionError(command)

    with override_environ({}):
        inst = Harness(tokens=tokens, quiet=True)
        exit_code = inst.persist_current()

    expect(
        exit_code == MISSING_EXIT_CODE,
        "persist_current should return 2 for missing variable",
    )


def test_apply_gui_values_reports_results() -> None:
    stored_values: dict[str, str] = {}
    tokens: list[tuple[str, str]] = [("ALPHA", "Alpha"), ("BETA", "Beta")]

    class Harness(x_cls_make_persistent_env_var_x):
        def set_user_env(self) -> bool:
            stored_values[self.var] = self.value
            return True

        def get_user_env(self) -> str | None:
            return stored_values.get(self.var)

    values: dict[str, str] = {"ALPHA": "top-secret", "BETA": ""}

    summaries, ok_all = Harness(tokens=tokens, quiet=True).apply_gui_values(values)

    expect(not ok_all, "apply_gui_values should report incomplete application")
    expect_equal(
        summaries,
        [("ALPHA", True, "top-secret"), ("BETA", False, "<empty>")],
        label="apply_gui_values summaries",
    )


def test_run_gui_uses_instance_tokens() -> None:
    tokens: list[tuple[str, str]] = [("CUSTOM", "Custom")]
    inst = x_cls_make_persistent_env_var_x(tokens=tokens, quiet=True)

    call_log: list[tuple[tuple[tuple[str, str], ...], dict[str, object]]] = []

    def fake_open_gui(
        tokens: Sequence[tuple[str, str]], *, ctx: object | None, quiet: bool
    ) -> dict[str, str] | None:
        call_log.append((tuple(tokens), {"ctx": ctx, "quiet": quiet}))
        return None

    def fake_prompt(
        tokens: Sequence[tuple[str, str]], quiet: bool
    ) -> dict[str, str] | None:
        prompt_calls.append((tuple(tokens), quiet))
        return {}

    prompt_calls: list[tuple[tuple[tuple[str, str], ...], bool]] = []

    with override_open_gui(fake_open_gui), override_prompt_for_values(fake_prompt):
        exit_code = inst.run_gui()

    expect(
        exit_code == MISSING_EXIT_CODE,
        "run_gui should return 2 when GUI is cancelled",
    )
    expect(call_log, "open_gui should be invoked")
    recorded_tokens, kwargs = call_log[0]
    expect_equal(recorded_tokens, tuple(tokens), label="open_gui positional tokens")
    expect_equal(kwargs, {"ctx": None, "quiet": True}, label="open_gui kwargs")
    expect_equal(len(prompt_calls), 1, label="prompt_for_values invocation count")


@contextmanager
def override_environ(values: Mapping[str, str]) -> Iterator[None]:
    original = dict(os.environ)
    os.environ.clear()
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


@contextmanager
def override_open_gui(replacer: OpenGuiHook) -> Iterator[None]:
    open_gui_attr = "_open_gui_and_collect"
    original = cast("OpenGuiHook", getattr(module, open_gui_attr))

    def recorder(
        tokens: Sequence[tuple[str, str]], *, ctx: object | None, quiet: bool
    ) -> dict[str, str] | None:
        return replacer(tokens, ctx=ctx, quiet=quiet)

    setattr(module, open_gui_attr, recorder)
    try:
        yield
    finally:
        setattr(module, open_gui_attr, original)


@contextmanager
def override_prompt_for_values(
    replacer: Callable[[Sequence[tuple[str, str]], bool], dict[str, str] | None],
) -> Iterator[None]:
    prompt_attr = "_prompt_for_values"
    original = cast(
        "Callable[..., dict[str, str] | None]", getattr(module, prompt_attr)
    )

    def wrapper(
        tokens: Sequence[tuple[str, str]], *, quiet: bool
    ) -> dict[str, str] | None:
        return replacer(tokens, quiet)

    setattr(module, prompt_attr, wrapper)
    try:
        yield
    finally:
        setattr(module, prompt_attr, original)
