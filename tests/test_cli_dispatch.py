from __future__ import annotations

import sys
from io import StringIO

import x_make_persistent_env_var_x.x_cls_make_persistent_env_var_x as module

EXPECTED_EXIT_CODE = 5


def expect(*, condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_launch_gui_flag_invokes_tk_runner() -> None:
    records: list[tuple[str, object]] = []

    original_run_gui = module.x_cls_make_persistent_env_var_x.run_gui

    def fake_run(self: module.x_cls_make_persistent_env_var_x) -> int:
        raw_quiet: object = getattr(self, "quiet", False)
        quiet_attr = bool(raw_quiet)
        records.append(("run", quiet_attr))
        return EXPECTED_EXIT_CODE

    module.x_cls_make_persistent_env_var_x.run_gui = fake_run  # type: ignore[method-assign]

    stdout_original = sys.stdout
    sys.stdout = StringIO()
    try:
        exit_code = module.run_cli(["--launch-gui", "--quiet"])
    finally:
        module.x_cls_make_persistent_env_var_x.run_gui = original_run_gui  # type: ignore[method-assign]
        sys.stdout = stdout_original

    expect(
        condition=exit_code == EXPECTED_EXIT_CODE,
        message="run_cli should return GUI exit code",
    )
    expect(
        condition=records == [("run", True)],
        message="run_gui should run with quiet flag",
    )
