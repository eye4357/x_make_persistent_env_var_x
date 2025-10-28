from __future__ import annotations

import sys
from io import StringIO

from x_make_persistent_env_var_x import (
    x_cls_make_persistent_env_var_x as module,
)


def test_launch_gui_flag_invokes_pyside_runner() -> None:
    records: list[str] = []

    class FakeGui:
        def __init__(self, *, quiet: bool = False, ctx: object | None = None) -> None:
            records.append(f"init:{quiet}")
            self._quiet = quiet
            self._ctx = ctx

        def run_gui(self) -> int:
            records.append("run")
            return 7

    try:
        from x_make_persistent_env_var_x import (
            x_cls_make_persistent_env_var_gui_x as gui_module,
        )
    except ImportError as exc:  # pragma: no cover - module is part of package
        raise AssertionError("GUI module missing") from exc

    original = gui_module.x_cls_make_persistent_env_var_gui_x
    gui_module.x_cls_make_persistent_env_var_gui_x = FakeGui

    stdout_original = sys.stdout
    sys.stdout = StringIO()
    try:
        exit_code = module._run_cli(["--launch-gui", "--quiet"])
    finally:
        gui_module.x_cls_make_persistent_env_var_gui_x = original
        sys.stdout = stdout_original

    assert exit_code == 7
    assert records == ["init:True", "run"]
