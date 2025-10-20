"""JSON contracts for x_make_persistent_env_var_x."""

from __future__ import annotations

_JSON_VALUE_SCHEMA: dict[str, object] = {
    "type": ["object", "array", "string", "number", "boolean", "null"],
}

_TOKEN_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "label": {"type": ["string", "null"], "minLength": 1},
        "required": {"type": "boolean"},
    },
    "required": ["name"],
    "additionalProperties": False,
}

_VALUES_SCHEMA: dict[str, object] = {
    "type": "object",
    "minProperties": 1,
    "additionalProperties": {"type": "string", "minLength": 1},
}

_ACTION_SCHEMA: dict[str, object] = {
    "type": "string",
    "enum": [
        "persist-current",
        "persist-values",
        "inspect",
    ],
}

_INPUT_PARAMETERS_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "action": _ACTION_SCHEMA,
        "tokens": {
            "type": "array",
            "items": _TOKEN_SCHEMA,
            "minItems": 1,
            "uniqueItems": True,
        },
        "values": _VALUES_SCHEMA,
        "quiet": {"type": "boolean"},
        "include_existing": {"type": "boolean"},
        "notes": {"type": "string"},
    },
    "required": ["action"],
    "additionalProperties": False,
    "allOf": [
        {
            "if": {"properties": {"action": {"const": "persist-values"}}},
            "then": {"required": ["values"]},
        },
    ],
}

_INPUT_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "x_make_persistent_env_var_x input",
    "type": "object",
    "properties": {
        "command": {"const": "x_make_persistent_env_var_x"},
        "parameters": _INPUT_PARAMETERS_SCHEMA,
    },
    "required": ["command", "parameters"],
    "additionalProperties": False,
}

_RESULT_ENTRY_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "label": {"type": ["string", "null"], "minLength": 1},
        "status": {
            "type": "string",
            "enum": [
                "persisted",
                "skipped",
                "failed",
                "unchanged",
            ],
        },
        "attempted": {"type": ["boolean", "null"]},
        "stored": {"type": ["string", "null"], "minLength": 1},
        "stored_hash": {"type": ["string", "null"], "minLength": 6},
        "message": {"type": ["string", "null"], "minLength": 1},
        "changed": {"type": "boolean"},
    },
    "required": ["name", "status", "changed"],
    "additionalProperties": False,
}

_SUMMARY_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "action": _ACTION_SCHEMA,
        "tokens_total": {"type": "integer", "minimum": 0},
        "tokens_modified": {"type": "integer", "minimum": 0},
        "tokens_skipped": {"type": "integer", "minimum": 0},
        "tokens_failed": {"type": "integer", "minimum": 0},
        "exit_code": {"type": "integer"},
        "quiet": {"type": "boolean"},
    },
    "required": [
        "action",
        "tokens_total",
        "tokens_modified",
        "tokens_skipped",
        "tokens_failed",
        "exit_code",
    ],
    "additionalProperties": True,
}

_OUTPUT_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "x_make_persistent_env_var_x output",
    "type": "object",
    "properties": {
        "status": {"const": "success"},
        "schema_version": {"const": "x_make_persistent_env_var_x.run/1.0"},
        "generated_at": {"type": "string", "format": "date-time"},
        "summary": _SUMMARY_SCHEMA,
        "results": {
            "type": "array",
            "items": _RESULT_ENTRY_SCHEMA,
        },
        "messages": {
            "type": "array",
            "items": {"type": "string"},
        },
        "environment_snapshot": {
            "type": "object",
            "additionalProperties": _JSON_VALUE_SCHEMA,
        },
    },
    "required": ["status", "schema_version", "generated_at", "summary"],
    "additionalProperties": False,
}

_ERROR_SCHEMA: dict[str, object] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "x_make_persistent_env_var_x error",
    "type": "object",
    "properties": {
        "status": {"const": "failure"},
        "message": {"type": "string", "minLength": 1},
        "exit_code": {"type": "integer"},
        "details": {
            "type": "object",
            "additionalProperties": _JSON_VALUE_SCHEMA,
        },
    },
    "required": ["status", "message"],
    "additionalProperties": True,
}

INPUT_SCHEMA = _INPUT_SCHEMA
OUTPUT_SCHEMA = _OUTPUT_SCHEMA
ERROR_SCHEMA = _ERROR_SCHEMA

__all__ = ["ERROR_SCHEMA", "INPUT_SCHEMA", "OUTPUT_SCHEMA"]
