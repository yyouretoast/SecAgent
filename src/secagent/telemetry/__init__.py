"""Telemetry trace-session contracts for SecAgent."""

from secagent.telemetry.callbacks import SecAgentTelemetryCallback, TraceSession
from secagent.telemetry.exporter import TraceExporter
from secagent.telemetry.hitl import HITLNormalizer, normalize_hitl, normalize_interrupt
from secagent.telemetry.otlp_adapter import convert_otlp_to_traces, is_otlp_payload
from secagent.telemetry.redactor import PIIRedactor, Redactor

__all__ = [
    "HITLNormalizer",
    "PIIRedactor",
    "Redactor",
    "SecAgentTelemetryCallback",
    "TraceExporter",
    "TraceSession",
    "convert_otlp_to_traces",
    "is_otlp_payload",
    "normalize_hitl",
    "normalize_interrupt",
]
