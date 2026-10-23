"""Schema-directed generation of tool arguments for attack scenarios."""

from __future__ import annotations

import inspect
import types
from typing import Annotated, Any, Union, get_args, get_origin


class SchemaDirectedFuzzer:
    """Build typed arguments and place an attack payload in a semantically suitable field."""

    _TARGETS = {
        "sqli": {"query", "sql", "search", "filter"},
        "command": {"server_id", "cmd", "command", "path", "script"},
        "egress": {"url", "endpoint", "destination"},
        "scope": {"fields", "columns", "attributes"},
    }

    def build_arguments(
        self,
        tool: Any,
        attack: str,
        payload: Any,
    ) -> dict[str, Any]:
        """Return arguments matching the known tool schema; inject only into a matching field."""
        specs = self._parameter_specs(tool)
        arguments = {
            name: self._valid_value(spec)
            for name, spec in specs.items()
            if spec.get("required", True) or spec.get("default") is not None
        }
        targets = self._TARGETS.get(attack, set())
        for name, spec in specs.items():
            annotation = spec.get("annotation")
            json_type = spec.get("type")
            is_string = self._is_string(annotation) or json_type == "string"
            if name.lower() in targets and is_string:
                arguments[name] = payload
                break
        return arguments

    @classmethod
    def _is_string(cls, annotation: Any) -> bool:
        if annotation in (str, "str"):
            return True
        origin = get_origin(annotation)
        if origin is Annotated:
            return cls._is_string(get_args(annotation)[0])
        if origin in (Union, types.UnionType):
            return any(
                cls._is_string(choice)
                for choice in get_args(annotation)
                if choice is not type(None)
            )
        return False

    @classmethod
    def _parameter_specs(cls, tool: Any) -> dict[str, dict[str, Any]]:
        if isinstance(tool, dict):
            return tool
        metadata = getattr(tool, "parameter_metadata", None)
        if metadata:
            return metadata

        schema_model = getattr(tool, "args_schema", None)
        if schema_model is not None:
            try:
                schema = schema_model.model_json_schema()
                required = set(schema.get("required", []))
                return {
                    name: {**details, "required": name in required}
                    for name, details in schema.get("properties", {}).items()
                }
            except (AttributeError, TypeError, ValueError):
                pass

        func = (
            tool
            if callable(tool)
            else (getattr(tool, "func", None) or getattr(tool, "coroutine", None))
        )
        if callable(func):
            try:
                signature = inspect.signature(func)
            except (TypeError, ValueError):
                return {}
            specs = {}
            for name, parameter in signature.parameters.items():
                if parameter.kind in (
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                ):
                    continue
                annotation = parameter.annotation
                specs[name] = {
                    "annotation": annotation,
                    "required": parameter.default is inspect.Parameter.empty,
                    "default": None
                    if parameter.default is inspect.Parameter.empty
                    else parameter.default,
                }
            return specs

        # Legacy ToolMetadata stores annotation names as strings.
        legacy = getattr(tool, "parameters", {})
        return {
            name: {
                "annotation": value,
                "type": cls._legacy_type(value),
                "required": True,
            }
            for name, value in legacy.items()
        }

    @staticmethod
    def _legacy_type(annotation: Any) -> str | None:
        label = str(annotation).lower()
        for known in ("string", "integer", "number", "boolean", "array", "object"):
            if known in label:
                return known
        if "str" in label:
            return "string"
        if "int" in label:
            return "integer"
        if "float" in label:
            return "number"
        if "bool" in label:
            return "boolean"
        return None

    @classmethod
    def _valid_value(cls, spec: dict[str, Any]) -> Any:
        if "default" in spec and spec["default"] is not None:
            return spec["default"]
        annotation = spec.get("annotation")
        json_type = spec.get("type")
        if annotation is inspect.Parameter.empty:
            annotation = None
        if annotation in (int, "int") or json_type == "integer":
            lower = spec.get("minimum", spec.get("ge", 0))
            upper = spec.get("maximum", spec.get("le"))
            value = max(10, lower) if isinstance(lower, (int, float)) else 10
            if isinstance(upper, (int, float)):
                value = min(value, upper)
            return int(value)
        if annotation in (float, "float") or json_type == "number":
            return spec.get("minimum", spec.get("ge", 1.0))
        if annotation in (bool, "bool") or json_type == "boolean":
            return False
        if annotation in (bytes, "bytes"):
            return b""
        if annotation in (list, "list") or json_type == "array":
            return []
        if annotation in (dict, "dict") or json_type == "object":
            return {}
        if isinstance(annotation, type):
            try:
                if issubclass(annotation, str):
                    return ""
            except TypeError:
                pass
        origin = get_origin(annotation)
        if origin is not None:
            choices = get_args(annotation)
            if origin is list:
                return []
            if choices:
                return cls._valid_value({"annotation": choices[0]})
        if json_type == "string" or annotation in (str, "str"):
            if spec.get("enum"):
                return spec["enum"][0]
            return "x" * max(0, spec.get("minLength", 0))
        return None
