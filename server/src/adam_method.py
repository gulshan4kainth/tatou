"""adam_method.py

Watermarking method for group member Adam.

Strategy: Inserts a JSON comment object just before the last EOF marker.
If no EOF is found, appends at the end. Uses a simple keyed SHA256 tag
for integrity (not encryption). Distinct marker line for separation.
"""
from __future__ import annotations

from typing import Final
import base64
import hashlib
import hmac
import json

from watermarking_method import (
    WatermarkingMethod,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
    load_pdf_bytes,
    PdfSource,
)


class AdamMethod(WatermarkingMethod):
    name: Final[str] = "adam"
    _MARKER: Final[bytes] = b"%%WM-ADAM:v1\n"
    _CTX: Final[bytes] = b"wm:group-adam:v1:"  # domain separation

    @staticmethod
    def get_usage() -> str:
        return "Embeds Adam watermark as marker+payload before final EOF; position ignored; key required." 

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be non-empty")
        if not key:
            raise ValueError("Key must be non-empty")
        s_bytes = secret.encode("utf-8")
        mac = hmac.new(key.encode("utf-8"), self._CTX + s_bytes, hashlib.sha256).hexdigest()
        obj = {"v":1, "mac":mac, "s": base64.b64encode(s_bytes).decode("ascii")}
        payload = base64.urlsafe_b64encode(json.dumps(obj, separators=(",",":"), ensure_ascii=True).encode("utf-8")) + b"\n"
        eof = b"%%EOF"
        idx = data.rfind(eof)
        if idx == -1:
            return data + b"\n" + self._MARKER + payload
        # Insert before EOF marker (keeping EOF at end)
        return data[:idx] + self._MARKER + payload + data[idx:]

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        return True

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        idx = data.rfind(self._MARKER)
        if idx == -1:
            raise SecretNotFoundError("No Adam watermark found")
        start = idx + len(self._MARKER)
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        line = data[start:end].strip()
        try:
            decoded = base64.urlsafe_b64decode(line)
            obj = json.loads(decoded)
        except Exception as exc:
            raise SecretNotFoundError("Malformed Adam watermark") from exc
        if obj.get("v") != 1:
            raise WatermarkingError("Unsupported Adam watermark version")
        try:
            mac = str(obj["mac"])
            secret_b64 = obj["s"].encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid Adam payload fields") from exc
        expected = hmac.new(key.encode("utf-8"), self._CTX + secret_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            raise InvalidKeyError("Key failed to authenticate Adam watermark")
        return secret_bytes.decode("utf-8")

__all__ = ["AdamMethod"]
