"""Recursive redaction of PII and credentials before trace serialization."""

from __future__ import annotations

import re
from typing import Any


class PIIRedactor:
    """Scrub supported sensitive values while preserving container structure."""

    SSN_PATTERN = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
    TOKEN_PATTERN = re.compile(
        r"\b(?:sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{36}|Bearer\s+[A-Za-z0-9_\-\.]{20,})\b"
    )
    CARD_PATTERN = re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")

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
            return {key: cls.scrub_container(value) for key, value in obj.items()}
        if isinstance(obj, list):
            return [cls.scrub_container(value) for value in obj]
        if isinstance(obj, tuple):
            return tuple(cls.scrub_container(value) for value in obj)
        return obj


Redactor = PIIRedactor
