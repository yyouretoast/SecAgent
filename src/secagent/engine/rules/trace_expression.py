"""Safe, zero-eval AST-based composable trace policy expression rule."""

from __future__ import annotations

import ast
import functools
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from secagent.engine.loader import PolicyDefinition
from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values

_STR_METHODS = frozenset({"lower", "upper", "strip", "startswith", "endswith"})
_MAPPING_METHODS = frozenset({"get", "keys"})
_SAFE_METHODS = _STR_METHODS | _MAPPING_METHODS
_BUILTIN_HELPER_NAMES = frozenset(
    {
        "contains",
        "matches",
        "domain_in",
        "has_prior_gate",
        "len",
        "any",
        "all",
        "str",
        "int",
        "float",
        "lower",
    }
)
_MAX_AST_NODES = 256
_MAX_AST_DEPTH = 32
_MAX_VALUE_SIZE = 100_000
_MAX_INT_BITS = 2048


@functools.lru_cache(maxsize=256)
def _compile_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _wrap_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _SafeProxy(value)
    if isinstance(value, list):
        return [_wrap_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_wrap_value(item) for item in value)
    return value


class _SafeProxy:
    """Read-only attribute/item proxy blocking private/dunder access."""

    __slots__ = ("_data",)

    def __init__(self, data: Mapping[str, Any]) -> None:
        self._data = data

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise ValueError(f"Access to private attribute '{name}' is forbidden")
        return _wrap_value(self._data.get(name))

    def __getitem__(self, key: Any) -> Any:
        return _wrap_value(self._data[key])

    def get(self, key: Any, default: Any = None) -> Any:
        return _wrap_value(self._data.get(key, default))

    def keys(self) -> list[Any]:
        return list(self._data.keys())

    def raw(self) -> Mapping[str, Any]:
        return self._data


def _unwrap(value: Any) -> Any:
    if isinstance(value, _SafeProxy):
        return value.raw()
    if isinstance(value, list):
        return [_unwrap(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_unwrap(item) for item in value)
    return value


def _fn_contains(obj: Any, needle: Any) -> bool:
    raw = _unwrap(obj)
    target = str(_unwrap(needle)).lower()
    if isinstance(raw, str):
        return target in raw.lower()
    if isinstance(raw, Mapping):
        if any(target in str(k).lower() for k in raw):
            return True
    return any(target in text.lower() for _, text in iter_string_values(raw))


def _fn_matches(obj: Any, pattern: Any) -> bool:
    raw = _unwrap(obj)
    compiled = _compile_regex(str(_unwrap(pattern)))
    if isinstance(raw, str):
        return compiled.search(raw) is not None
    return any(compiled.search(text) is not None for _, text in iter_string_values(raw))


def _fn_domain_in(span_obj: Any, allowed: Any) -> bool:
    from secagent.engine.rules.network_egress import _domain_allowed, _extract_hostnames

    raw_span = _unwrap(span_obj)
    if not isinstance(raw_span, Mapping):
        return False
    raw_allowed = _unwrap(allowed)
    if isinstance(raw_allowed, str):
        allowed_items: Sequence[Any] = (raw_allowed,)
    elif isinstance(raw_allowed, (list, tuple, set, frozenset)):
        allowed_items = tuple(raw_allowed)
    else:
        allowed_items = ()
    allowed_set = {
        str(item).strip().lower().rstrip(".") for item in allowed_items if str(item).strip()
    }
    params = raw_span.get("input_parameters", {})
    hosts: list[str] = []
    for path, text in iter_string_values(params):
        hosts.extend(_extract_hostnames(text, path))
    return bool(hosts) and all(_domain_allowed(host, allowed_set) for host in hosts)


def _check_depth(node: ast.AST, depth: int = 0) -> None:
    if depth > _MAX_AST_DEPTH:
        raise ValueError(f"trace_expression exceeds maximum AST depth ({_MAX_AST_DEPTH})")
    for child in ast.iter_child_nodes(node):
        _check_depth(child, depth + 1)


def _validate_ast(tree: ast.AST, allowed_vars: frozenset[str] | None = None) -> None:
    allowed_nodes = (
        ast.Expression,
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.UnaryOp,
        ast.Not,
        ast.UAdd,
        ast.USub,
        ast.BinOp,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Mod,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.In,
        ast.NotIn,
        ast.Is,
        ast.IsNot,
        ast.IfExp,
        ast.Constant,
        ast.Name,
        ast.Load,
        ast.List,
        ast.Tuple,
        ast.Set,
        ast.Subscript,
        ast.Attribute,
        ast.Call,
        ast.keyword,
    )
    _check_depth(tree)
    nodes = list(ast.walk(tree))
    if len(nodes) > _MAX_AST_NODES:
        raise ValueError(f"trace_expression exceeds maximum AST size ({_MAX_AST_NODES} nodes)")
    valid_names = (allowed_vars or frozenset({"span", "trace", "index"})) | _BUILTIN_HELPER_NAMES
    for node in nodes:
        if not isinstance(node, allowed_nodes):
            raise ValueError(f"Unsupported expression syntax: {type(node).__name__}")
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and len(node.value) > _MAX_VALUE_SIZE:
                raise ValueError(
                    f"trace_expression string literal exceeds max length ({_MAX_VALUE_SIZE})"
                )
            if (
                isinstance(node.value, int)
                and not isinstance(node.value, bool)
                and node.value.bit_length() > _MAX_INT_BITS
            ):
                raise ValueError(
                    f"trace_expression integer literal exceeds max bits ({_MAX_INT_BITS})"
                )
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise ValueError(f"Private attribute access forbidden: {node.attr}")
        if isinstance(node, ast.Name) and node.id not in valid_names:
            raise ValueError(f"Unknown identifier in trace_expression: '{node.id}'")
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg is None:
                    raise ValueError("**kwargs unpacking is not allowed in trace_expression")
            if isinstance(node.func, ast.Name):
                if node.func.id not in _BUILTIN_HELPER_NAMES:
                    raise ValueError(
                        f"Call to non-whitelisted function in trace_expression: '{node.func.id}'"
                    )
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr not in _SAFE_METHODS:
                    raise ValueError(
                        f"Call to non-whitelisted method in trace_expression: '{node.func.attr}'"
                    )
            else:
                raise ValueError("Dynamic callable targets are not allowed in trace_expression")


def compile_trace_expression(
    source: str,
    *,
    allowed_vars: Sequence[str] | None = None,
) -> ast.Expression:
    """Parse and validate a safe trace policy expression."""
    try:
        parsed = ast.parse(source, mode="eval")
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise ValueError(f"Invalid trace_expression syntax: {exc}") from exc
    var_set = frozenset(allowed_vars) if allowed_vars is not None else None
    _validate_ast(parsed, allowed_vars=var_set)
    return parsed


def _bound_result(value: Any) -> Any:
    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value.bit_length() > _MAX_INT_BITS
    ):
        raise OverflowError("Integer result exceeds maximum allowed bit width")
    if isinstance(value, (str, bytes, list, tuple)) and len(value) > _MAX_VALUE_SIZE:
        raise ValueError(f"Sequence result exceeds maximum allowed size ({_MAX_VALUE_SIZE})")
    return value


def _eval_node(
    node: ast.AST, env: Mapping[str, Any], funcs: Mapping[str, Callable[..., Any]]
) -> Any:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, env, funcs)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        if node.id in funcs:
            return funcs[node.id]
        raise ValueError(f"Unknown identifier in trace_expression: '{node.id}'")
    if isinstance(node, ast.List):
        return [_eval_node(el, env, funcs) for el in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_eval_node(el, env, funcs) for el in node.elts)
    if isinstance(node, ast.Set):
        return {_eval_node(el, env, funcs) for el in node.elts}
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            result: Any = True
            for value in node.values:
                result = _eval_node(value, env, funcs)
                if not result:
                    return result
            return result
        result = False
        for value in node.values:
            result = _eval_node(value, env, funcs)
            if result:
                return result
        return result
    if isinstance(node, ast.UnaryOp):
        operand = _unwrap(_eval_node(node.operand, env, funcs))
        if isinstance(node.op, ast.Not):
            return not operand
        if isinstance(node.op, ast.USub):
            return _bound_result(-operand)
        return _bound_result(+operand)
    if isinstance(node, ast.BinOp):
        left = _unwrap(_eval_node(node.left, env, funcs))
        right = _unwrap(_eval_node(node.right, env, funcs))
        if isinstance(node.op, ast.Add):
            if (
                isinstance(left, (str, bytes, list, tuple))
                and isinstance(right, (str, bytes, list, tuple))
                and len(left) + len(right) > _MAX_VALUE_SIZE
            ):
                raise ValueError(
                    f"Sequence result exceeds maximum allowed size ({_MAX_VALUE_SIZE})"
                )
            return _bound_result(left + right)
        if isinstance(node.op, ast.Sub):
            return _bound_result(left - right)
        if isinstance(node.op, ast.Mult):
            if not (
                isinstance(left, (int, float))
                and not isinstance(left, bool)
                and isinstance(right, (int, float))
                and not isinstance(right, bool)
            ):
                raise TypeError("Sequence multiplication is disallowed in trace_expression")
            return _bound_result(left * right)
        if isinstance(node.op, ast.Div):
            return _bound_result(left / right)
        return _bound_result(left % right)
    if isinstance(node, ast.Compare):
        left = _unwrap(_eval_node(node.left, env, funcs))
        for op, comparator in zip(node.ops, node.comparators, strict=True):
            right = _unwrap(_eval_node(comparator, env, funcs))
            ok = False
            if isinstance(op, ast.Eq):
                ok = left == right
            elif isinstance(op, ast.NotEq):
                ok = left != right
            elif isinstance(op, ast.Lt):
                ok = left < right
            elif isinstance(op, ast.LtE):
                ok = left <= right
            elif isinstance(op, ast.Gt):
                ok = left > right
            elif isinstance(op, ast.GtE):
                ok = left >= right
            elif isinstance(op, ast.In):
                ok = left in right
            elif isinstance(op, ast.NotIn):
                ok = left not in right
            elif isinstance(op, ast.Is):
                ok = left is right
            elif isinstance(op, ast.IsNot):
                ok = left is not right
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, ast.IfExp):
        cond = _eval_node(node.test, env, funcs)
        return _eval_node(node.body if cond else node.orelse, env, funcs)
    if isinstance(node, ast.Attribute):
        target = _eval_node(node.value, env, funcs)
        if isinstance(target, _SafeProxy):
            return getattr(target, node.attr)
        if isinstance(target, str) and node.attr in _STR_METHODS:
            return getattr(target, node.attr)
        if isinstance(target, Mapping) and node.attr in _MAPPING_METHODS:
            return getattr(target, node.attr)
        raise ValueError(f"Disallowed attribute access '{node.attr}' on {type(target).__name__}")
    if isinstance(node, ast.Subscript):
        target = _eval_node(node.value, env, funcs)
        key = _unwrap(_eval_node(node.slice, env, funcs))
        return target[key]
    if isinstance(node, ast.Call):
        fn = _eval_node(node.func, env, funcs)
        args = [_eval_node(arg, env, funcs) for arg in node.args]
        kwargs = {kw.arg: _eval_node(kw.value, env, funcs) for kw in node.keywords if kw.arg}
        if fn in funcs.values() or (callable(fn) and getattr(fn, "__name__", "") in _SAFE_METHODS):
            return fn(*args, **kwargs)
        raise ValueError("Call to non-whitelisted function in trace_expression")
    raise ValueError(f"Unsupported AST node: {type(node).__name__}")


class TraceExpressionRule(BaseRule):
    """Evaluate a declarative AST-sandboxed single-span or temporal trace predicate."""

    def __init__(self, policy: PolicyDefinition) -> None:
        super().__init__(policy)
        self._expr_source = str(policy.condition["expression"])
        self._sequence = tuple(str(v) for v in policy.condition.get("sequence", ()))
        allowed_vars = (*self._sequence, "trace") if self._sequence else ("span", "trace", "index")
        self._compiled = compile_trace_expression(self._expr_source, allowed_vars=allowed_vars)
        self._target_tiers = set(policy.condition.get("target_tiers", ()))
        self._target_tools = set(policy.condition.get("target_tools", ()))

    def _helper_funcs(
        self,
        spans: Sequence[Mapping[str, Any]],
        gate_state: dict[str, Any],
    ) -> dict[str, Callable[..., Any]]:
        consumed_by: dict[int, int] = gate_state["consumed_by"]

        def has_prior_gate(
            span_obj: Any,
            name: str = "approval_gate",
            require_operation: bool = False,
        ) -> bool:
            target = _unwrap(span_obj)
            if not isinstance(target, Mapping):
                return False
            target_idx = next(
                (i for i, cand in enumerate(spans) if cand is target),
                -1,
            )
            if target_idx < 0:
                target_id = target.get("span_id")
                target_idx = next(
                    (
                        i
                        for i, cand in enumerate(spans)
                        if target_id and cand.get("span_id") == target_id
                    ),
                    -1,
                )
            if target_idx <= 0:
                return False
            if gate_state["force_no_gate"]:
                return False
            target_tool = str(target.get("name") or "")
            for pos in range(target_idx - 1, -1, -1):
                if pos in consumed_by and consumed_by[pos] != target_idx:
                    continue
                candidate = spans[pos]
                if (
                    candidate.get("span_type") == "gate.hitl"
                    and candidate.get("name") == name
                    and candidate.get("approval_granted") is True
                    and not candidate.get("is_error", False)
                ):
                    if not require_operation:
                        gate_state["pending"].append((pos, target_idx))
                        return True
                    op = (candidate.get("input_parameters") or {}).get("operation")
                    if op == target_tool:
                        gate_state["pending"].append((pos, target_idx))
                        return True
            return False

        return {
            "contains": _fn_contains,
            "matches": _fn_matches,
            "domain_in": _fn_domain_in,
            "has_prior_gate": has_prior_gate,
            "len": lambda x: len(_unwrap(x)),
            "any": lambda x: any(_unwrap(x)),
            "all": lambda x: all(_unwrap(x)),
            "str": lambda x: str(_unwrap(x)),
            "int": lambda x: int(_unwrap(x)),
            "float": lambda x: float(_unwrap(x)),
            "lower": lambda x: str(_unwrap(x)).lower(),
        }

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        spans = [s for s in trace.get("spans", ()) if isinstance(s, Mapping)]
        gate_state: dict[str, Any] = {
            "consumed_by": {},
            "pending": [],
            "force_no_gate": False,
        }
        funcs = self._helper_funcs(spans, gate_state)
        trace_proxy = _SafeProxy(trace)
        violations: list[PolicyViolation] = []
        eval_errors = (
            KeyError,
            IndexError,
            TypeError,
            ValueError,
            ZeroDivisionError,
            AttributeError,
            OverflowError,
            re.error,
        )

        def _eval_with_gate_commit(env: Mapping[str, Any]) -> bool:
            gate_state["force_no_gate"] = False
            gate_state["pending"].clear()
            try:
                matched = bool(_eval_node(self._compiled, env, funcs))
            except eval_errors:
                matched = False
            if not matched and gate_state["pending"]:
                claimed = list(gate_state["pending"])
                gate_state["force_no_gate"] = True
                try:
                    matched_without_gate = bool(_eval_node(self._compiled, env, funcs))
                except eval_errors:
                    matched_without_gate = False
                finally:
                    gate_state["force_no_gate"] = False
                if matched_without_gate:
                    for gate_pos, owner_idx in claimed:
                        gate_state["consumed_by"].setdefault(gate_pos, owner_idx)
            return matched

        if not self._sequence:
            for idx, span in enumerate(spans):
                if self._target_tiers or self._target_tools:
                    if (
                        span.get("permission_tier") not in self._target_tiers
                        and span.get("name") not in self._target_tools
                    ):
                        continue
                env = {"span": _SafeProxy(span), "trace": trace_proxy, "index": idx}
                if _eval_with_gate_commit(env):
                    violations.append(
                        self.violation(
                            span,
                            {
                                "expression": self._expr_source,
                                "matched_span_id": span.get("span_id"),
                            },
                        )
                    )
            return violations

        if len(self._sequence) == 2:
            first_var, second_var = self._sequence
            flagged_dst_ids: set[int] = set()
            for i, src in enumerate(spans):
                for j in range(i + 1, len(spans)):
                    if j in flagged_dst_ids:
                        continue
                    dst = spans[j]
                    if self._target_tiers or self._target_tools:
                        if (
                            dst.get("permission_tier") not in self._target_tiers
                            and dst.get("name") not in self._target_tools
                        ):
                            continue
                    env = {
                        first_var: _SafeProxy(src),
                        second_var: _SafeProxy(dst),
                        "trace": trace_proxy,
                    }
                    if _eval_with_gate_commit(env):
                        flagged_dst_ids.add(j)
                        violations.append(
                            self.violation(
                                dst,
                                {
                                    "expression": self._expr_source,
                                    "sequence": list(self._sequence),
                                    "matched_spans": {
                                        first_var: src.get("span_id"),
                                        second_var: dst.get("span_id"),
                                    },
                                },
                            )
                        )
        return violations
