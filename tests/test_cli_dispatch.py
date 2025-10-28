from __future__ import annotations

import sys
from collections.abc import Callable
from io import StringIO
from typing import Any, cast

import x_make_persistent_env_var_x.x_cls_make_persistent_env_var_x as module

_run_cli = cast("Callable[[list[str]], int]", module._run_cli)

def test_launch_gui_flag_invokes_tk_runner() -> None:
    records: list[tuple[str, Any]] = []

    original_run_gui = module.x_cls_make_persistent_env_var_x.run_gui

    def fake_run(self: object) -> int:
        quiet = cast("bool", getattr(self, "quiet", False))
        records.append(("run", quiet))
        return 5

    module.x_cls_make_persistent_env_var_x.run_gui = fake_run  # type: ignore[assignment]

    stdout_original = sys.stdout
    sys.stdout = StringIO()
    try:
        exit_code = _run_cli(["--launch-gui", "--quiet"])
    finally:
        module.x_cls_make_persistent_env_var_x.run_gui = original_run_gui  # type: ignore[assignment]
        sys.stdout = stdout_original

    assert exit_code == 5
    assert records == [("run", True)]
