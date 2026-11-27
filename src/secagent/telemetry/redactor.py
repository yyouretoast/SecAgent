"""Recursive redaction of PII and credentials before trace serialization."""

from __future__ import annotations

import re
from typing import Any


class PIIRedactor:
    """Scrub supported sensitive values while preserving container structure."""

    SSN_PATTERN = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
    PEM_PATTERN = re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
        r"|(?:[ \t]*\r?\n[A-Za-z0-9+/=]{1,80})*(?:[ \t]+[A-Za-z0-9+/=]{8,})?)"
    )
    TOKEN_PATTERN = re.compile(
        r"(?<![A-Za-z0-9_])(?:"
        r"sk-[A-Za-z0-9_\-]{20,}|"
        r"gh[pousr]_[A-Za-z0-9]{20,}|"
        r"github_pat_[A-Za-z0-9_]{20,}|"
        r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
        r"AIza[0-9A-Za-z_\-]{35}|"
        r"xox[baprs]-[0-9A-Za-z\-]{10,}|"
        r"eyJ[A-Za-z0-9_\-]{4,}\.eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{8,}|"
        r"(?i:Bearer)\s+[A-Za-z0-9_\-\.+=/]{20,}"
        r")(?![A-Za-z0-9_])"
    )
    CARD_PATTERN = re.compile(r"\b(?:\d[ -]?){12,15}\d\b")

    @classmethod
    def _validate_luhn(cls, card_str: str) -> bool:
        digits = [int(char) for char in card_str if char.isdigit()]
        if len(digits) not in (13, 14, 15, 16):
            return False
        checksum = 0
        for index, digit in enumerate(reversed(digits)):
            if index % 2:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    @classmethod
    def scrub_text(cls, text: str) -> str:
        text = cls.PEM_PATTERN.sub("[REDACTED_PRIVATE_KEY]", text)
        text = cls.SSN_PATTERN.sub("[REDACTED_SSN]", text)
        text = cls.TOKEN_PATTERN.sub("[REDACTED_TOKEN]", text)

        def replace_card(match: re.Match[str]) -> str:
            value = match.group(0)
            return "[REDACTED_CARD]" if cls._validate_luhn(value) else value

        return cls.CARD_PATTERN.sub(replace_card, text)

    @classmethod
    def scrub_container(cls, obj: Any) -> Any:
        if isinstance(obj, str):
            return cls.scrub_text(obj)
        if isinstance(obj, dict):
            return {
                (cls.scrub_text(key) if isinstance(key, str) else key): cls.scrub_container(value)
                for key, value in obj.items()
            }
        if isinstance(obj, list):
            return [cls.scrub_container(value) for value in obj]
        if isinstance(obj, tuple):
            return tuple(cls.scrub_container(value) for value in obj)
        return obj


Redactor = PIIRedactor
