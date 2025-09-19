"""PSM_watermarking.py

PSM-specific watermarking method implementation.

Strategy:
- Append a distinct marker and a compact JSON payload after EOF.
- Payload carries base64 secret and a keyed BLAKE2b-128 tag for integrity.

Compatible with the WatermarkingMethod interface used by the app.
"""
from __future__ import annotations

from typing import Final
import base64
import hashlib
import json
import hmac

from watermarking_method import (
    WatermarkingMethod,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
    load_pdf_bytes,
    PdfSource,
)


class PSMWatermarking(WatermarkingMethod):
    name: Final[str] = "psm"
    _MAGIC: Final[bytes] = b"\n%%WM-PSM:v1\n"
    _CTX: Final[bytes] = b"wm:group-psm:v1:"

    @staticmethod
    def get_usage() -> str:
        return "Embeds PSM watermark after EOF using keyed BLAKE2b integrity tag."

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be non-empty")
        if not key:
            raise ValueError("Key must be non-empty")
        s_bytes = secret.encode("utf-8")
        tag = hashlib.blake2b(self._CTX + s_bytes, key=key.encode("utf-8"), digest_size=16).hexdigest()
        obj = {"v": 1, "alg": "BLAKE2b-128", "tag": tag, "s": base64.b64encode(s_bytes).decode("ascii")}
        payload = base64.urlsafe_b64encode(json.dumps(obj, separators=(",",":"), ensure_ascii=True).encode("utf-8"))
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        return True

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No PSM watermark found")
        start = idx + len(self._MAGIC)
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        line = data[start:end].strip()
        try:
            decoded = base64.urlsafe_b64decode(line)
            obj = json.loads(decoded)
        except Exception as exc:
            raise SecretNotFoundError("Malformed PSM watermark") from exc
        if obj.get("v") != 1 or obj.get("alg") != "BLAKE2b-128":
            raise WatermarkingError("Unsupported PSM watermark version/alg")
        try:
            tag = str(obj["tag"])
            secret_b64 = obj["s"].encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid PSM payload fields") from exc
        expected = hashlib.blake2b(self._CTX + secret_bytes, key=key.encode("utf-8"), digest_size=16).hexdigest()
        if not hmac.compare_digest(tag, expected):
            raise InvalidKeyError("Key failed to authenticate PSM watermark")
        return secret_bytes.decode("utf-8")

__all__ = ["PSMWatermarking"]
