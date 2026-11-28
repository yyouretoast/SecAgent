"""Schema-directed generation of tool arguments for attack scenarios."""

from __future__ import annotations

import inspect
import types
from typing import Annotated, Any, Union, get_args, get_origin


class SchemaDirectedFuzzer:
    """Build typed arguments and place an attack payload in a semantically suitable field."""

    _TARGETS = {
        "sqli": {
            "query",
            "sql",
            "search",
            "filter",
            "filter_val",
            "where",
            "statement",
            "input",
            "text",
            "prompt",
        },
        "command": {
            "server_id",
            "cmd",
            "command",
            "path",
            "script",
            "target",
            "hostname",
            "filename",
            "arg",
            "payload",
            "body",
        },
        "egress": {
            "url",
            "endpoint",
            "destination",
            "uri",
            "webhook",
            "host",
            "callback",
            "target",
        },
        "scope": {"fields", "columns", "attributes", "select", "projection"},
    }

    @classmethod
    def _spec_has_json_type(cls, spec: dict[str, Any], wanted: str) -> bool:
        if spec.get("type") == wanted:
            return True
        for key in ("anyOf", "oneOf"):
            variants = spec.get(key)
            if isinstance(variants, list) and any(
                isinstance(v, dict) and v.get("type") == wanted for v in variants
            ):
                return True
        return False

    @classmethod
    def _is_array(cls, annotation: Any) -> bool:
        if annotation in (list, "list"):
            return True
        if isinstance(annotation, str):
            norm = annotation.strip().lower()
            if norm in ("<class 'list'>", "list") or norm.startswith(
                ("list[", "typing.list[", "sequence[")
            ):
                return True
        origin = get_origin(annotation)
        if origin is list:
            return True
        if origin is Annotated:
            return cls._is_array(get_args(annotation)[0])
        if origin in (Union, types.UnionType):
            return any(
                cls._is_array(choice) for choice in get_args(annotation) if choice is not type(None)
            )
        return False

    def build_arguments(
        self,
        tool: Any,
        attack: str,
        payload: Any,
        *,
        fallback_to_any_string: bool = False,
    ) -> dict[str, Any]:
        """Return arguments matching the known tool schema; inject only into a matching field."""
        specs = self._parameter_specs(tool)
        arguments = {
            name: self._valid_value(spec)
            for name, spec in specs.items()
            if spec.get("required", True) or spec.get("default") is not None
        }
        targets = self._TARGETS.get(attack, set())
        injected = False
        first_string_param: str | None = None
        for name, spec in specs.items():
            annotation = spec.get("annotation")
            is_string = self._is_string(annotation) or self._spec_has_json_type(spec, "string")
            is_array = self._is_array(annotation) or self._spec_has_json_type(spec, "array")
            if is_string and first_string_param is None:
                first_string_param = name
            if name.lower() in targets:
                if isinstance(payload, list) and is_array:
                    arguments[name] = list(payload)
                    injected = True
                    break
                if is_string:
                    arguments[name] = (
                        ",".join(str(x) for x in payload) if isinstance(payload, list) else payload
                    )
                    injected = True
                    break
        if not injected and fallback_to_any_string and first_string_param is not None:
            arguments[first_string_param] = (
                ",".join(str(x) for x in payload) if isinstance(payload, list) else payload
            )
        return arguments

    @classmethod
    def _is_string(cls, annotation: Any) -> bool:
        if annotation in (str, "str"):
            return True
        if isinstance(annotation, str):
            parts = [p.strip().lower() for p in annotation.split("|")]
            for p in parts:
                if p in ("str", "<class 'str'>", "optional[str]", "typing.optional[str]"):
                    return True
                if p.startswith(("union[", "typing.union[")) and "str" in p:
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
        if annotation is inspect.Parameter.empty or annotation == "<class 'inspect._empty'>":
            annotation = None
        if json_type is None:
            for key in ("anyOf", "oneOf"):
                variants = spec.get(key)
                if isinstance(variants, list):
                    non_null = [
                        v for v in variants if isinstance(v, dict) and v.get("type") != "null"
                    ]
                    if non_null:
                        return cls._valid_value(non_null[0])
        if json_type is None and isinstance(annotation, str):
            norm = annotation.strip().lower()
            if norm in ("<class 'str'>", "str"):
                json_type = "string"
            elif norm in ("<class 'int'>", "int"):
                json_type = "integer"
            elif norm in ("<class 'float'>", "float"):
                json_type = "number"
            elif norm in ("<class 'bool'>", "bool"):
                json_type = "boolean"
            elif norm in ("<class 'list'>", "list") or norm.startswith(("list[", "typing.list[")):
                json_type = "array"
            elif norm in ("<class 'dict'>", "dict") or norm.startswith(("dict[", "typing.dict[")):
                json_type = "object"
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
            if origin is Annotated and choices:
                return cls._valid_value({"annotation": choices[0]})
            if origin is list:
                return []
            if origin is dict:
                return {}
            if origin is set:
                return set()
            if origin is tuple:
                return ()
            if origin in (Union, types.UnionType):
                non_none = [c for c in choices if c is not type(None)]
                if non_none:
                    return cls._valid_value({"annotation": non_none[0]})
                return None
            if choices:
                return cls._valid_value({"annotation": choices[0]})
        if json_type == "string" or annotation in (str, "str"):
            if spec.get("enum"):
                return spec["enum"][0]
            return "x" * max(0, spec.get("minLength", 0))
        return None
