"""Small RFC 8785 JSON Canonicalization Scheme implementation for JSON values."""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import Any


_MAX_SAFE_INTEGER = (1 << 53) - 1


def _normalize_string(value: str) -> str:
    """Combine valid escaped surrogate pairs and reject lone UTF-16 surrogates."""
    result: list[str] = []
    index = 0
    while index < len(value):
        code = ord(value[index])
        if 0xD800 <= code <= 0xDBFF:
            if index + 1 >= len(value):
                raise ValueError("JCS strings cannot contain unpaired surrogates")
            low = ord(value[index + 1])
            if not 0xDC00 <= low <= 0xDFFF:
                raise ValueError("JCS strings cannot contain unpaired surrogates")
            result.append(chr(0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)))
            index += 2
            continue
        if 0xDC00 <= code <= 0xDFFF:
            raise ValueError("JCS strings cannot contain unpaired surrogates")
        result.append(value[index])
        index += 1
    return "".join(result)


def _quote(value: str) -> str:
    normalized = _normalize_string(value)
    return json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))


def _float(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("JCS does not support NaN or infinity")
    if value == 0:
        return "0"

    negative = value < 0
    decimal = Decimal(repr(abs(value)))
    digits = "".join(str(digit) for digit in decimal.as_tuple().digits)
    exponent = decimal.as_tuple().exponent
    while len(digits) > 1 and digits.endswith("0"):
        digits = digits[:-1]
        exponent += 1
    point = len(digits) + exponent

    if point > 0 and point <= 21:
        if point >= len(digits):
            rendered = digits + ("0" * (point - len(digits)))
        else:
            rendered = digits[:point] + "." + digits[point:]
    elif point <= 0 and point > -6:
        rendered = "0." + ("0" * (-point)) + digits
    else:
        scientific_exponent = point - 1
        coefficient = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")
        sign = "+" if scientific_exponent >= 0 else ""
        rendered = f"{coefficient}e{sign}{scientific_exponent}"
    return ("-" if negative else "") + rendered


def _canonical(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, int):
        if abs(value) <= _MAX_SAFE_INTEGER:
            return str(value)
        try:
            as_binary64 = float(value)
        except OverflowError as exc:
            raise ValueError("JCS number is outside the IEEE-754 range") from exc
        if not math.isfinite(as_binary64) or int(as_binary64) != value:
            raise ValueError("JCS integer cannot be represented exactly as an IEEE-754 value")
        return _float(as_binary64)
    if isinstance(value, float):
        return _float(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JCS object keys must be strings")
        normalized = [(_normalize_string(key), item) for key, item in value.items()]
        if len({key for key, _ in normalized}) != len(normalized):
            raise ValueError("JCS object keys collide after Unicode normalization")
        normalized.sort(key=lambda pair: pair[0].encode("utf-16-be"))
        return "{" + ",".join(_quote(key) + ":" + _canonical(item) for key, item in normalized) + "}"
    raise ValueError("JCS supports JSON values only")


def canonicalize(value: Any) -> bytes:
    """Return canonical UTF-8 bytes for a JSON-compatible Python value."""
    return _canonical(value).encode("utf-8")


def fingerprint(value: Any) -> str:
    """Compute SHA-256 over RFC 8785 canonical JSON bytes."""
    return hashlib.sha256(canonicalize(value)).hexdigest()
