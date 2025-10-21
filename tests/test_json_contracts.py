from __future__ import annotations

# ruff: noqa: S101 - assertions express expectations in test cases
import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from x_make_common_x.json_contracts import validate_payload, validate_schema

from x_make_persistent_env_var_x.json_contracts import (
    ERROR_SCHEMA,
    INPUT_SCHEMA,
    OUTPUT_SCHEMA,
)
from x_make_persistent_env_var_x.x_cls_make_persistent_env_var_x import (
    main_json,
    x_cls_make_persistent_env_var_x,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "json_contracts"
REPORTS_DIR = Path(__file__).resolve().parents[1] / "reports"


@pytest.fixture(scope="module")  # type: ignore[arg-type]
def sample_input() -> Iterator[dict[str, object]]:
    with (FIXTURE_DIR / "input.json").open("r", encoding="utf-8") as handle:
        yield json.load(handle)


@pytest.fixture(scope="module")  # type: ignore[arg-type]
def sample_output() -> Iterator[dict[str, object]]:
    with (FIXTURE_DIR / "output.json").open("r", encoding="utf-8") as handle:
        yield json.load(handle)


@pytest.fixture(scope="module")  # type: ignore[arg-type]
def sample_error() -> Iterator[dict[str, object]]:
    with (FIXTURE_DIR / "error.json").open("r", encoding="utf-8") as handle:
        yield json.load(handle)


def _create_fake_run(
    user_env: dict[str, str],
) -> Callable[[str], subprocess.CompletedProcess[str]]:
    def fake_run(command: str) -> subprocess.CompletedProcess[str]:
        parts = command.split('"')
        if "SetEnvironmentVariable" in command:
            name = parts[1]
            value = parts[3]
            user_env[name] = value
            return subprocess.CompletedProcess(
                ["powershell", "-Command", command],
                returncode=0,
                stdout="",
                stderr="",
            )
        if "GetEnvironmentVariable" in command:
            name = parts[1]
            value = user_env.get(name, "")
            return subprocess.CompletedProcess(
                ["powershell", "-Command", command],
                returncode=0,
                stdout=value,
                stderr="",
            )
        raise AssertionError(command)

    return fake_run


def _entries_by_name(result: Mapping[str, object]) -> dict[str, dict[str, object]]:
    results_obj = result.get("results")
    entries: dict[str, dict[str, object]] = {}
    if isinstance(results_obj, list):
        for entry_obj in results_obj:
            if not isinstance(entry_obj, dict):
                continue
            name_value = entry_obj.get("name")
            if isinstance(name_value, str):
                entries[name_value] = entry_obj
    return entries


def _snapshot_mappings(
    result: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    snapshot_obj = result.get("environment_snapshot")
    if not isinstance(snapshot_obj, dict):
        message = "snapshot missing"
        raise TypeError(message)
    provided_obj = snapshot_obj.get("provided")
    user_obj = snapshot_obj.get("user")
    if not isinstance(provided_obj, dict) or not isinstance(user_obj, dict):
        message = "snapshot payload malformed"
        raise TypeError(message)
    return provided_obj, user_obj


def test_schemas_are_valid() -> None:
    for schema in (INPUT_SCHEMA, OUTPUT_SCHEMA, ERROR_SCHEMA):
        validate_schema(schema)


def test_sample_payloads_match_schema(
    sample_input: dict[str, object],
    sample_output: dict[str, object],
    sample_error: dict[str, object],
) -> None:
    validate_payload(sample_input, INPUT_SCHEMA)
    validate_payload(sample_output, OUTPUT_SCHEMA)
    validate_payload(sample_error, ERROR_SCHEMA)


def test_existing_reports_align_with_schema() -> None:
    if not REPORTS_DIR.exists():
        pytest.skip("no reports directory for persistent env tool")
    report_files = sorted(REPORTS_DIR.glob("x_make_persistent_env_var_x_run_*.json"))
    if not report_files:
        pytest.skip("no persistent env run reports to validate")
    for report_file in report_files:
        with report_file.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        validate_payload(payload, OUTPUT_SCHEMA)


def test_main_json_persist_values_success(
    sample_input: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.loads(json.dumps(sample_input))
    user_env: dict[str, str] = {"DEBUG": "0"}
    fake_run = _create_fake_run(user_env)

    for name, value in (("API_TOKEN", "session-secret"), ("DEBUG", "0")):
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        x_cls_make_persistent_env_var_x,
        "run_powershell",
        staticmethod(fake_run),
    )

    result = main_json(payload)

    validate_payload(result, OUTPUT_SCHEMA)
    status_value = result.get("status")
    assert isinstance(status_value, str)
    assert status_value == "success"

    summary_obj = result.get("summary")
    assert isinstance(summary_obj, dict)
    expected_summary = {
        "action": "persist-values",
        "tokens_modified": 2,
        "tokens_failed": 0,
        "exit_code": 0,
    }
    actual_summary = {key: summary_obj.get(key) for key in expected_summary}
    assert actual_summary == expected_summary

    entries = _entries_by_name(result)
    api_result = entries["API_TOKEN"]
    assert api_result.get("status") == "persisted"
    assert api_result.get("changed") is True
    assert api_result.get("stored") == "<hidden>"
    assert isinstance(api_result.get("stored_hash"), str)

    debug_result = entries["DEBUG"]
    assert debug_result.get("status") == "persisted"
    assert debug_result.get("stored") == "1"

    provided_snapshot, user_snapshot = _snapshot_mappings(result)
    assert provided_snapshot.get("API_TOKEN") == "<hidden>"
    assert user_snapshot.get("DEBUG") == "1"


def test_main_json_persist_current_handles_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "command": "x_make_persistent_env_var_x",
        "parameters": {
            "action": "persist-current",
            "tokens": [
                {"name": "ALPHA", "label": "Alpha", "required": True},
                {"name": "BETA", "label": "Beta", "required": False},
            ],
            "quiet": True,
            "include_existing": False,
        },
    }

    user_env: dict[str, str] = {}

    def fake_run(command: str) -> subprocess.CompletedProcess[str]:
        if "SetEnvironmentVariable" in command:
            parts = command.split('"')
            name = parts[1]
            value = parts[3]
            user_env[name] = value
            return subprocess.CompletedProcess(
                ["powershell", "-Command", command],
                returncode=0,
                stdout="",
                stderr="",
            )
        if "GetEnvironmentVariable" in command:
            parts = command.split('"')
            name = parts[1]
            value = user_env.get(name, "")
            return subprocess.CompletedProcess(
                ["powershell", "-Command", command],
                returncode=0,
                stdout=value,
                stderr="",
            )
        raise AssertionError(command)

    monkeypatch.setenv("ALPHA", "session-alpha")
    monkeypatch.delenv("BETA", raising=False)
    monkeypatch.setattr(
        x_cls_make_persistent_env_var_x,
        "run_powershell",
        staticmethod(fake_run),
    )

    result = main_json(payload)

    validate_payload(result, OUTPUT_SCHEMA)
    summary_obj = result.get("summary")
    assert isinstance(summary_obj, dict)
    assert summary_obj.get("tokens_modified") == 1
    assert summary_obj.get("tokens_skipped") == 1
    assert summary_obj.get("tokens_failed") == 0
    assert summary_obj.get("exit_code") == 0

    results_obj = result.get("results")
    assert isinstance(results_obj, list)
    entries: dict[str, dict[str, object]] = {}
    for entry_obj in results_obj:
        if not isinstance(entry_obj, dict):
            continue
        name_value = entry_obj.get("name")
        if isinstance(name_value, str):
            entries[name_value] = entry_obj
    alpha_entry = entries.get("ALPHA")
    assert isinstance(alpha_entry, dict)
    assert alpha_entry.get("status") in {"persisted", "unchanged"}
    beta_entry = entries.get("BETA")
    assert isinstance(beta_entry, dict)
    assert beta_entry.get("status") == "skipped"
    assert beta_entry.get("attempted") is False
    assert beta_entry.get("changed") is False


def test_main_json_reports_validation_errors() -> None:
    payload = {
        "command": "x_make_persistent_env_var_x",
        "parameters": {"action": "invalid"},
    }

    result = main_json(payload)

    validate_payload(result, ERROR_SCHEMA)
    status_value = result.get("status")
    message_value = result.get("message")
    assert isinstance(status_value, str)
    assert isinstance(message_value, str)
    assert status_value == "failure"
    assert message_value == "input payload failed validation"
