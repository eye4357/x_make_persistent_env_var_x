from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .x_cls_make_persistent_env_var_x import (
    TokenSpec,
    _collect_prefill,
    main_json,
)

try:  # pragma: no cover - PySide6 is optional at import time
    import PySide6.QtCore as _QtCoreRaw
    import PySide6.QtWidgets as _QtWidgetsRaw
except ModuleNotFoundError as exc:  # pragma: no cover - deferred until GUI use
    _PYSIDE_LOAD_ERROR = exc
    _QtCoreRaw = None
    _QtWidgetsRaw = None
else:  # pragma: no cover - no behavioural impact
    _PYSIDE_LOAD_ERROR = None


_QUIT_FLAG_PROPERTY = "_x_runner_disable_quit_on_last_window_closed"
_QUIT_ORIGINAL_PROPERTY = "_x_runner_original_quit_on_last_window_closed"


class _PySideMissingError(RuntimeError):
    """Raised when the PySide6 dependency is not present."""

    def __init__(self) -> None:
        message = (
            "PySide6 is required for the environment vault dialog. "
            "Install it with 'pip install PySide6'."
        )
        super().__init__(message)


def _require_pyside() -> tuple[Any, Any]:
    if _QtCoreRaw is None or _QtWidgetsRaw is None:
        raise _PySideMissingError from _PYSIDE_LOAD_ERROR
    return _QtCoreRaw, _QtWidgetsRaw


def _ensure_application(QtWidgets: Any) -> tuple[Any, bool]:
    app = QtWidgets.QApplication.instance()
    if app is not None:
        return app, False
    app = QtWidgets.QApplication(["persistent-env-vault"])
    return app, True


def _mark_quit_suppressed(app: Any, original: bool) -> None:
    app.setProperty(_QUIT_FLAG_PROPERTY, True)
    app.setProperty(_QUIT_ORIGINAL_PROPERTY, bool(original))
    app.setQuitOnLastWindowClosed(False)


def restore_quit_behavior_if_needed(app: Any) -> None:
    """Re-enable Qt's quit-on-last-window-closed behaviour if we disabled it."""

    if not bool(app.property(_QUIT_FLAG_PROPERTY)):
        return

    original = app.property(_QUIT_ORIGINAL_PROPERTY)
    fallback = True if original is None else bool(original)
    try:
        app.setQuitOnLastWindowClosed(fallback)
    finally:
        app.setProperty(_QUIT_FLAG_PROPERTY, False)
        app.setProperty(_QUIT_ORIGINAL_PROPERTY, None)


class x_cls_make_persistent_env_var_gui_x:  # noqa: N801 - external contract
    """PySide6 GUI runner that orchestrates JSON persistence operations."""

    def __init__(
        self,
        *,
        quiet: bool = False,
        ctx: object | None = None,
        tokens: Sequence[tuple[str, str]] | None = None,
        token_specs: Sequence[TokenSpec] | None = None,
    ) -> None:
        from .x_cls_make_persistent_env_var_x import x_cls_make_persistent_env_var_x

        options: dict[str, object] = {}
        if token_specs is not None:
            options["token_specs"] = token_specs
        elif tokens is not None:
            options["tokens"] = tokens
        self._service = x_cls_make_persistent_env_var_x(
            "",
            "",
            quiet=quiet,
            ctx=ctx,
            **options,
        )
        self.quiet = quiet
        self._ctx = ctx

    @property
    def token_specs(self) -> Sequence[TokenSpec]:
        return self._service.token_specs

    @property
    def tokens(self) -> Sequence[tuple[str, str]]:
        return self._service.tokens

    def run_gui(self) -> int:
        QtCore, QtWidgets = _require_pyside()
        app, created_app = _ensure_application(QtWidgets)
        if created_app:
            original_quit = bool(app.quitOnLastWindowClosed())
            _mark_quit_suppressed(app, original_quit)
        prefill = _collect_prefill(self.tokens, ctx=self._ctx, quiet=self.quiet)
        app_thread = app.thread()
        current_thread = QtCore.QThread.currentThread()

        if current_thread != app_thread:
            class _DialogExecutor(QtCore.QObject):
                @QtCore.Slot(result=int)
                def execute(self) -> int:  # type: ignore[override]
                    dialog_obj = _build_dialog(QtCore, QtWidgets, runner=self_runner, prefill=prefill)
                    dialog_obj.exec()
                    return int(getattr(dialog_obj, "exit_code", 2))

            self_runner = self
            executor = _DialogExecutor()
            executor.moveToThread(app_thread)
            try:
                exit_code = QtCore.QMetaObject.invokeMethod(  # type: ignore[assignment]
                    executor,
                    "execute",
                    QtCore.Qt.BlockingQueuedConnection,
                )
            finally:
                QtCore.QMetaObject.invokeMethod(
                    executor,
                    "deleteLater",
                    QtCore.Qt.QueuedConnection,
                )
            exit_code = int(exit_code) if exit_code is not None else 2
        else:
            dialog = _build_dialog(QtCore, QtWidgets, self, prefill)
            dialog.exec()
            exit_code = dialog.exit_code
        if created_app:
            # Leave the quit-on-last-window toggle disabled until the main GUI
            # is ready. Flush pending events so the temporary dialog state
            # does not linger.
            app.processEvents()
        return exit_code


def _build_dialog(
    QtCore: Any,
    QtWidgets: Any,
    runner: x_cls_make_persistent_env_var_gui_x,
    prefill: Mapping[str, str],
) -> Any:
    class _PersistentEnvDialog(QtWidgets.QDialog):
        def __init__(self) -> None:
            super().__init__()
            self.exit_code: int = 2
            self._entries: dict[str, Any] = {}
            self._status_label = None
            self._build_ui()

        def _build_ui(self) -> None:
            self.setWindowTitle("Persist Environment Tokens")
            self.resize(440, 260)

            layout = QtWidgets.QVBoxLayout(self)

            description = QtWidgets.QLabel(
                "Provide values for each token. Values are persisted to the user's "
                "environment scope."
            )
            description.setWordWrap(True)
            layout.addWidget(description)

            form_layout = QtWidgets.QFormLayout()
            for spec in runner.token_specs:
                label = QtWidgets.QLabel(spec.display_label or spec.name)
                entry = QtWidgets.QLineEdit()
                entry.setEchoMode(QtWidgets.QLineEdit.Password)
                stored_value = prefill.get(spec.name)
                if stored_value:
                    entry.setText(stored_value)
                entry.setPlaceholderText(spec.display_label or spec.name)
                form_layout.addRow(label, entry)
                self._entries[spec.name] = entry
            layout.addLayout(form_layout)

            toggle = QtWidgets.QCheckBox("Show values")
            toggle.toggled.connect(self._handle_toggle_visibility)  # type: ignore[arg-type]
            layout.addWidget(toggle)

            status = QtWidgets.QLabel()
            status.setWordWrap(True)
            status.setVisible(False)
            layout.addWidget(status)
            self._status_label = status

            layout.addSpacing(12)

            buttons = QtWidgets.QHBoxLayout()
            buttons.addStretch(1)

            persist_button = QtWidgets.QPushButton("Set Tokens")
            persist_button.setDefault(True)
            persist_button.setAutoDefault(True)
            persist_button.clicked.connect(self._handle_persist_values)  # type: ignore[arg-type]
            buttons.addWidget(persist_button)

            cancel_button = QtWidgets.QPushButton("Cancel")
            cancel_button.clicked.connect(self.reject)  # type: ignore[arg-type]
            buttons.addWidget(cancel_button)

            layout.addLayout(buttons)


        def _handle_toggle_visibility(self, checked: bool) -> None:
            mode = (
                QtWidgets.QLineEdit.Normal
                if checked
                else QtWidgets.QLineEdit.Password
            )
            for entry in self._entries.values():
                entry.setEchoMode(mode)

        def _token_payloads(self, names: Iterable[str] | None = None) -> list[dict[str, object]]:
            if names is not None:
                name_set = {name for name in names}
                if not name_set:
                    return []
            else:
                name_set = None
            return [
                {
                    "name": spec.name,
                    "label": spec.display_label,
                    "required": spec.required,
                }
                for spec in runner.token_specs
                if name_set is None or spec.name in name_set
            ]

        def _persist(self, parameters: dict[str, object]) -> tuple[int, list[str]]:
            payload = {
                "command": "x_make_persistent_env_var_x",
                "parameters": parameters,
            }
            result = main_json(payload, ctx=runner._ctx)
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
                QtWidgets.QMessageBox.critical(self, "Persistence failed", message)
                return 1, []

            summary = result.get("summary")
            exit_code = 1
            if isinstance(summary, Mapping):
                code_obj = summary.get("exit_code")
                if isinstance(code_obj, int):
                    exit_code = code_obj
            messages = []
            raw_messages = result.get("messages")
            if isinstance(raw_messages, Sequence):
                messages = [str(item) for item in raw_messages if item]
            return exit_code, messages

        def reject(self) -> None:  # type: ignore[override]
            self.exit_code = 2
            super().reject()

        def _handle_persist_values(self) -> None:
            self._show_status("")

            provided_values: dict[str, str] = {}
            session_backfill: set[str] = set()
            missing_required: list[str] = []
            for spec in runner.token_specs:
                value = self._entries[spec.name].text().strip()
                if value:
                    provided_values[spec.name] = value
                    continue
                session_value = os.environ.get(spec.name)
                if session_value:
                    session_backfill.add(spec.name)
                    continue
                if spec.required:
                    missing_required.append(spec.display_label or spec.name)

            if missing_required:
                message = "Provide values for: " + ", ".join(missing_required)
                QtWidgets.QMessageBox.warning(self, "Tokens required", message)
                return

            if not provided_values and not session_backfill:
                QtWidgets.QMessageBox.information(
                    self,
                    "No values provided",
                    "Provide at least one token value before persisting.",
                )
                return

            aggregated_messages: list[str] = []
            had_failure = False

            def _apply(parameters: dict[str, object]) -> bool:
                nonlocal had_failure
                exit_code, messages = self._persist(parameters)
                if exit_code == 1 and not messages:
                    return False
                aggregated_messages.extend(messages)
                if exit_code == 1:
                    had_failure = True
                return True

            if provided_values:
                parameters_values: dict[str, object] = {
                    "action": "persist-values",
                    "tokens": self._token_payloads(provided_values.keys()),
                    "values": provided_values,
                    "quiet": runner.quiet,
                    "include_existing": True,
                }
                if not _apply(parameters_values):
                    return

            if not had_failure and session_backfill:
                parameters_session: dict[str, object] = {
                    "action": "persist-current",
                    "tokens": self._token_payloads(session_backfill),
                    "quiet": runner.quiet,
                    "include_existing": True,
                }
                if not _apply(parameters_session):
                    return

            if had_failure:
                summary = aggregated_messages or [
                    "Token persistence reported an error. Adjust the values and try again.",
                ]
                self.exit_code = 1
                self._show_status("\n".join(summary), is_error=True)
                return

            self.exit_code = 0
            if aggregated_messages:
                self._show_status("\n".join(aggregated_messages))
            self.accept()

        def _show_status(self, message: str, *, is_error: bool = False) -> None:
            if not self._status_label:
                return
            if not message:
                self._status_label.hide()
                self._status_label.setText("")
                return
            color = "#a33" if is_error else "#555"
            self._status_label.setStyleSheet(f"color: {color};")
            self._status_label.setText(message)
            self._status_label.show()

    return _PersistentEnvDialog()


__all__ = [
    "restore_quit_behavior_if_needed",
    "x_cls_make_persistent_env_var_gui_x",
]
