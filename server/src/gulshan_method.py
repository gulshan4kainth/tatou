"""gulshan_method.py

Simple watermarking method for Group member Gulshan.

Strategy: Append a structured marker block containing a hex SHA256 of the
secret+key context plus the secret itself in base64, after the final EOF.
This is similar in spirit to the existing toy method but uses a distinct
marker and context string so it can coexist without collisions.
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


class GulshanMethod(WatermarkingMethod):
    name: Final[str] = "gulshan"
    _MAGIC: Final[bytes] = b"\n%%WM-GULSHAN:v1\n"
    _CTX: Final[bytes] = b"wm:group-gulshan:v1:"  # domain separation

    @staticmethod
    def get_usage() -> str:
        return "Embeds a Gulshan watermark after EOF; position ignored; key used for HMAC integrity." 

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be non-empty")
        if not key:
            raise ValueError("Key must be non-empty")
        secret_bytes = secret.encode("utf-8")
        mac = hmac.new(key.encode("utf-8"), self._CTX + secret_bytes, hashlib.sha256).hexdigest()
        payload_obj = {"v":1, "alg":"HMAC-SHA256", "mac":mac, "s": base64.b64encode(secret_bytes).decode("ascii")}
        payload = base64.urlsafe_b64encode(json.dumps(payload_obj, separators=(",",":"), ensure_ascii=True).encode("utf-8"))
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
            raise SecretNotFoundError("No Gulshan watermark found")
        start = idx + len(self._MAGIC)
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        try:
            decoded = base64.urlsafe_b64decode(b64_payload)
            obj = json.loads(decoded)
        except Exception as exc:
            raise SecretNotFoundError("Malformed Gulshan watermark") from exc
        if obj.get("v") != 1 or obj.get("alg") != "HMAC-SHA256":
            raise WatermarkingError("Unsupported Gulshan watermark version/alg")
        try:
            mac_hex = str(obj["mac"])
            secret_b64 = obj["s"].encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Invalid Gulshan payload fields") from exc
        expected = hmac.new(key.encode("utf-8"), self._CTX + secret_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Key failed to authenticate Gulshan watermark")
        return secret_bytes.decode("utf-8")

__all__ = ["GulshanMethod"]
