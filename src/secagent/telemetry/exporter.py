"""Redact, validate, and serialize trace documents."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import jsonschema

from secagent.telemetry.redactor import PIIRedactor


class TraceExporter:
    """Validate trace documents against the repository's frozen JSON schema."""

    def __init__(self, schema_path: str | Path | None = None) -> None:
        default_schema = Path(__file__).resolve().parents[3] / "schemas" / "trace_event.schema.json"
        self.schema_path = Path(schema_path) if schema_path else default_schema
        with self.schema_path.open(encoding="utf-8") as handle:
            self.schema = json.load(handle)
        jsonschema.Draft202012Validator.check_schema(self.schema)

    @staticmethod
    def redact(trace: dict[str, Any]) -> dict[str, Any]:
        document = copy.deepcopy(trace)
        for span in document.get("spans", []):
            for field in ("input_parameters", "output_result", "error_message"):
                if field in span:
                    span[field] = PIIRedactor.scrub_container(span[field])
        return document

    def validate(self, trace: dict[str, Any]) -> dict[str, Any]:
        document = self.redact(trace)
        validator = jsonschema.Draft202012Validator(
            self.schema,
            format_checker=jsonschema.FormatChecker(),
        )
        errors = sorted(validator.iter_errors(document), key=lambda error: str(list(error.path)))
        if errors:
            messages = "; ".join(error.message for error in errors)
            raise jsonschema.ValidationError(messages)
        return document

    def export(self, trace: dict[str, Any], output_path: str | Path) -> dict[str, Any]:
        document = self.validate(trace)
        destination = Path(output_path)
        destination.write_text(json.dumps(document, indent=2), encoding="utf-8")
        return document
