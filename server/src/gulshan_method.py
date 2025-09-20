"""gulshan_method.py

Robust Gulshan watermark method using a valid incremental PDF update.

Strategy:
- Append a new indirect object whose compressed stream contains a JSON
  payload: base64 secret and an HMAC-SHA256 over (file_hash || secret).
- Update xref/trailer with Prev to form a valid incremental revision.
- This survives simple truncation and naive re-saves; removal requires
  object-level editing and will be detectable if a digital signature is added.
"""
from __future__ import annotations

from typing import Final
import base64
import hashlib
import hmac
import json
import re
import zlib

from watermarking_method import (
    WatermarkingMethod,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
    load_pdf_bytes,
    PdfSource,
)


_OBJ_HEADER_RE = re.compile(rb"(\d+)\s+0\s+obj\b")
_STARTXREF_RE = re.compile(rb"startxref\s*(\d+)\s*%%EOF", re.DOTALL)
_WM_OBJ_RE = re.compile(
    rb"(\d+)\s+0\s+obj\s*<<[^>]*?/SubType\s*/GLSN[^>]*?/Length\s+(\d+)[^>]*?>>\s*stream\s",
    re.DOTALL,
)


class GulshanMethod(WatermarkingMethod):
    name: Final[str] = "gulshan"
    _CTX: Final[bytes] = b"wm:group-gulshan:v2:"  # domain separation

    @staticmethod
    def get_usage() -> str:
        return (
            "Embeds Gulshan watermark as a new PDF object via incremental update; key used for HMAC integrity."
        )

    # --- PDF helpers ---
    def _find_last_startxref(self, data: bytes) -> int | None:
        m = list(_STARTXREF_RE.finditer(data))
        if not m:
            return None
        return int(m[-1].group(1))

    def _max_object_number(self, data: bytes) -> int:
        max_num = 0
        for m in _OBJ_HEADER_RE.finditer(data):
            try:
                n = int(m.group(1))
                if n > max_num:
                    max_num = n
            except Exception:
                continue
        return max_num

    def _penultimate_eof_end(self, data: bytes):
        positions = [m.start() for m in re.finditer(rb"%%EOF", data)]
        if len(positions) >= 2:
            return positions[-2] + len(b"%%EOF")
        elif positions:
            return positions[0] + len(b"%%EOF")
        return None

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        data = load_pdf_bytes(pdf)
        if not secret:
            raise ValueError("Secret must be non-empty")
        if not key:
            raise ValueError("Key must be non-empty")

        # Bind to original file hash (pre-append, or penultimate EOF)
        pen_eof = self._penultimate_eof_end(data)
        orig_region = data if pen_eof is None else data[:pen_eof]
        file_hash = hashlib.sha256(orig_region).hexdigest()

        s_bytes = secret.encode("utf-8")
        mac = hmac.new(key.encode("utf-8"), self._CTX + bytes.fromhex(file_hash) + s_bytes, hashlib.sha256).hexdigest()
        payload = json.dumps(
            {"v": 1, "alg": "HMAC-SHA256", "file": file_hash, "s": base64.b64encode(s_bytes).decode("ascii"), "mac": mac},
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        comp = zlib.compress(payload)
        length = len(comp)

        old_startxref = self._find_last_startxref(data)
        max_obj = self._max_object_number(data)
        new_obj = max_obj + 1 if max_obj > 0 else 1

        obj_header = f"{new_obj} 0 obj\n".encode()
        obj_dict = (
            b"<< /Type /WMARK /SubType /GLSN "
            b"/Filter /FlateDecode "
            + f"/Length {length} ".encode()
            + b"/V 1 >>\n"
        )
        stream_start = b"stream\n"
        stream_end = b"\nendstream\nendobj\n"
        obj_bytes = obj_header + obj_dict + stream_start + comp + stream_end

        object_offset = len(data) + 1  # account for leading \n
        xref_start = object_offset + len(obj_bytes)
        xref = (
            b"xref\n"
            + f"{new_obj} 1\n".encode()
            + f"{object_offset:010d} 00000 n \n".encode()
        )
        size = new_obj + 1
        if old_startxref is None:
            trailer = (
                b"trailer\n<< "
                + f"/Size {size} ".encode()
                + b">>\n"
            )
        else:
            trailer = (
                b"trailer\n<< "
                + f"/Size {size} ".encode()
                + f"/Prev {old_startxref} ".encode()
                + b">>\n"
            )
        startxref = b"startxref\n" + str(xref_start).encode() + b"\n%%EOF\n"

        appended = b"\n" + obj_bytes + xref + trailer + startxref
        return data + appended

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        return True

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        # Find GLSN watermark object (prefer newest)
        matches = list(_WM_OBJ_RE.finditer(data))
        if not matches:
            raise SecretNotFoundError("No Gulshan watermark object found")
        m = matches[-1]
        length = int(m.group(2))
        stream_pos = m.end()
        stream_bytes = data[stream_pos:stream_pos + length]
        try:
            payload = zlib.decompress(stream_bytes)
        except Exception as e:
            raise SecretNotFoundError("Gulshan watermark stream decompression failed") from e

        try:
            obj = json.loads(payload.decode("utf-8"))
            if obj.get("v") != 1 or obj.get("alg") != "HMAC-SHA256":
                raise WatermarkingError("Unsupported Gulshan watermark version/alg")
            file_hex = str(obj["file"]).lower()
            mac_hex = str(obj["mac"]).lower()
            secret_b64 = obj["s"].encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
        except Exception as exc:
            raise SecretNotFoundError("Malformed Gulshan payload") from exc

        # Recompute original file hash (use penultimate EOF if present)
        pen_eof = self._penultimate_eof_end(data)
        orig_region = data if pen_eof is None else data[:pen_eof]
        calc_file_hex = hashlib.sha256(orig_region).hexdigest()
        if calc_file_hex.lower() != file_hex:
            # The file content changed; treat as tampering
            raise InvalidKeyError("File binding mismatch (tampered)")

        expected = hmac.new(key.encode("utf-8"), self._CTX + bytes.fromhex(file_hex) + secret_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Key failed to authenticate Gulshan watermark")
        return secret_bytes.decode("utf-8")

__all__ = ["GulshanMethod"]
