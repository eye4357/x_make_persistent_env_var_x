from __future__ import annotations

import os
import subprocess
import unittest
from collections.abc import Callable
from typing import cast
from unittest import mock

import x_cls_make_persistent_env_var_x as module

x_cls_make_persistent_env_var_x = module.x_cls_make_persistent_env_var_x

SafeCall = Callable[[Callable[[], object]], bool]
TryEmit = Callable[..., None]
ApplyGuiValues = Callable[
    [dict[str, str]], tuple[list[tuple[str, bool, str | None]], bool]
]


class PersistentEnvTests(unittest.TestCase):
    def test_safe_call_and_try_emit(self) -> None:
        calls: list[str] = []

        def raise_error() -> None:
            error_message = "boom"
            raise RuntimeError(error_message)

        def record_success() -> None:
            calls.append("success")

        def should_not_run() -> None:
            calls.append("unreachable")

        safe_call = cast("SafeCall", module._safe_call)
        try_emit = cast("TryEmit", module._try_emit)

        self.assertFalse(safe_call(raise_error))
        self.assertTrue(safe_call(record_success))
        self.assertEqual(calls, ["success"])

        calls.clear()
        try_emit(raise_error, record_success, should_not_run)
        self.assertEqual(calls, ["success"])

    def test_persist_current_sets_present_variables(self) -> None:
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

        with mock.patch.object(
            x_cls_make_persistent_env_var_x,
            "run_powershell",
            side_effect=fake_run,
        ), mock.patch.dict(os.environ, {"FOO": "secret"}, clear=True):
            inst = x_cls_make_persistent_env_var_x(tokens=tokens, quiet=True)
            exit_code = inst.persist_current()

        self.assertEqual(exit_code, 0)
        self.assertEqual(state["FOO"], "secret")

    def test_persist_current_skips_missing_variables(self) -> None:
        tokens: list[tuple[str, str]] = [("FOO", "Foo token")]

        with mock.patch.object(
            x_cls_make_persistent_env_var_x,
            "run_powershell",
            side_effect=AssertionError,
        ), mock.patch.dict(os.environ, {}, clear=True):
            inst = x_cls_make_persistent_env_var_x(tokens=tokens, quiet=True)
            exit_code = inst.persist_current()

        self.assertEqual(exit_code, 2)

    def test_apply_gui_values_reports_results(self) -> None:
        stored_values: dict[str, str] = {}
        tokens: list[tuple[str, str]] = [("ALPHA", "Alpha"), ("BETA", "Beta")]
        inst = x_cls_make_persistent_env_var_x(tokens=tokens, quiet=True)

        def fake_set(self: x_cls_make_persistent_env_var_x) -> bool:
            stored_values[self.var] = self.value
            return True

        def fake_get(self: x_cls_make_persistent_env_var_x) -> str | None:
            return stored_values.get(self.var)

        values: dict[str, str] = {"ALPHA": "top-secret", "BETA": ""}

        with mock.patch.object(
            x_cls_make_persistent_env_var_x,
            "set_user_env",
            new=fake_set,
        ), mock.patch.object(
            x_cls_make_persistent_env_var_x,
            "get_user_env",
            new=fake_get,
        ):
            apply_gui_values = cast("ApplyGuiValues", inst._apply_gui_values)
            summaries, ok_all = apply_gui_values(values)

        self.assertFalse(ok_all)
        self.assertEqual(
            summaries,
            [("ALPHA", True, "top-secret"), ("BETA", False, "<empty>")],
        )

    def test_run_gui_uses_instance_tokens(self) -> None:
        tokens: list[tuple[str, str]] = [("CUSTOM", "Custom")]
        inst = x_cls_make_persistent_env_var_x(tokens=tokens, quiet=True)

        with mock.patch.object(
            module, "_open_gui_and_collect", return_value=None
        ) as mocked_open:
            exit_code = inst.run_gui()

        self.assertEqual(exit_code, 2)
        args, kwargs = mocked_open.call_args
        self.assertEqual(args[0], tuple(tokens))
        self.assertEqual(kwargs, {"ctx": None, "quiet": True})


if __name__ == "__main__":
    unittest.main()
