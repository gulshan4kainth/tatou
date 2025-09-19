"""
XOR-CTR + HMAC Incremental-Object watermarking method (non-AEAD alternative)

Drop this file into your project root (same level as watermarking_method.py and watermarking_utils.py).
Implements a WatermarkingMethod named "xorpdf-incremental" that protects the secret using a
standard-library-only scheme:
  - Confidentiality: XOR stream cipher built from SHA-256 in counter mode (no external deps)
  - Integrity: HMAC-SHA256 over (file_hash || salt || ciphertext)
  - File binding: includes SHA-256 of the original PDF (pre-append) in HMAC input

It appends a **valid incremental PDF revision** that introduces one new indirect object whose
compressed stream holds a compact JSON payload with the ciphertext, salt, and MAC.

This avoids conflicts with AEAD-based methods and comment-based schemes, and survives many
rewrite operations that preserve incremental updates.
"""
from __future__ import annotations
from typing import Final
import os
import re
import json
import time
import base64
import hashlib
import hmac
import zlib

from watermarking_method import (
    WatermarkingMethod, PdfSource, load_pdf_bytes,
    WatermarkingError, SecretNotFoundError, InvalidKeyError,
)

_B64 = lambda b: base64.urlsafe_b64encode(b).decode("ascii")
_B64D = lambda s: base64.urlsafe_b64decode(s.encode("ascii"))

# Regex helpers
_OBJ_HEADER_RE = re.compile(rb"(\d+)\s+0\s+obj\b")
_STARTXREF_RE = re.compile(rb"startxref\s*(\d+)\s*%%EOF", re.DOTALL)
_WM_OBJ_RE = re.compile(
    rb"(\d+)\s+0\s+obj\s*<<[^>]*?/SubType\s*/WMX[^>]*?/Length\s+(\d+)[^>]*?>>\s*stream\s",
    re.DOTALL,
)

class XORPDFIncrementalObject(WatermarkingMethod):
    name: Final[str] = "xorpdf-incremental"

    @staticmethod
    def get_usage() -> str:
        return (
            "Secret encrypted via XOR-CTR with SHA-256 keystream + HMAC-SHA256 integrity, "
            "stored in a new PDF object via incremental update. No external crypto deps."
        )

    # ---- crypto (stdlib) helpers ----
    def _sha256(self, b: bytes) -> bytes:
        return hashlib.sha256(b).digest()

    def _kdf(self, password: str, salt: bytes, length: int = 32) -> bytes:
        # Simple KDF: iterative SHA-256 over (password || salt). For coursework this is fine;
        # if you want stronger, switch to scrypt/PBKDF2 from 'hashlib' or 'cryptography'.
        data = password.encode("utf-8") + salt
        out = b""
        block = b""
        while len(out) < length:
            block = hashlib.sha256(block + data).digest()
            out += block
        return out[:length]

    def _keystream(self, key: bytes, nonce: bytes, nbytes: int) -> bytes:
        # SHA-256(counter || nonce || key) blocks concatenated
        out = bytearray()
        counter = 0
        while len(out) < nbytes:
            ctr_bytes = counter.to_bytes(8, "big")
            out.extend(hashlib.sha256(ctr_bytes + nonce + key).digest())
            counter += 1
        return bytes(out[:nbytes])

    def _xor(self, data: bytes, key_stream: bytes) -> bytes:
        return bytes(d ^ k for d, k in zip(data, key_stream))

    # ---- PDF helpers ----
    def _find_last_startxref(self, data: bytes) -> int:
        m = list(_STARTXREF_RE.finditer(data))
        if not m:
            raise WatermarkingError("Malformed PDF: no startxref found")
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

    # ---- interface ----
    def apply(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        data = load_pdf_bytes(pdf)
        if not key:
            raise ValueError("Key must be non-empty")

        # Original hash for file-binding (pre-append)
        orig_hash = self._sha256(data)

        # Derive keys and encrypt via XOR-CTR keystream
        salt = os.urandom(16)
        enc_key = self._kdf(key, salt, 32)
        nonce = os.urandom(12)
        pt = secret.encode("utf-8")
        ks = self._keystream(enc_key, nonce, len(pt))
        ct = self._xor(pt, ks)

        # Integrity (MAC) over file_hash || salt || nonce || ct
        mac_key = self._kdf("mac:" + key, salt, 32)
        mac = hmac.new(mac_key, orig_hash + salt + nonce + ct, hashlib.sha256).hexdigest()

        payload = json.dumps({
            "v": 1,
            "kdf": "sha256-iter",
            "salt": _B64(salt),
            "nonce": _B64(nonce),
            "file": hashlib.sha256(data).hexdigest(),
            "ts": int(time.time()),
            "ct": _B64(ct),
            "mac": mac,
        }, separators=(",",":")) .encode()

        comp = zlib.compress(payload)
        length = len(comp)

        # Prepare incremental object
        old_startxref = self._find_last_startxref(data)
        max_obj = self._max_object_number(data)
        new_obj = max_obj + 1 if max_obj > 0 else 1

        obj_header = f"{new_obj} 0 obj\n".encode()
        obj_dict = (
            b"<< /Type /WMARK /SubType /WMX "
            b"/Filter /FlateDecode "
            + f"/Length {length} ".encode()
            + b"/V 1 >>\n"
        )
        stream_start = b"stream\n"
        stream_end = b"\nendstream\nendobj\n"
        obj_bytes = obj_header + obj_dict + stream_start + comp + stream_end

        # Compute offsets for xref/trailer
        object_offset = len(data) + 1  # +1 for leading \n below
        xref_start = object_offset + len(obj_bytes)

        xref = (
            b"xref\n"
            + f"{new_obj} 1\n".encode()
            + f"{object_offset:010d} 00000 n \n".encode()
        )
        size = new_obj + 1
        trailer = (
            b"trailer\n<< "
            + f"/Size {size} ".encode()
            + f"/Prev {old_startxref} ".encode()
            + b">>\n"
        )
        startxref = b"startxref\n" + str(xref_start).encode() + b"\n%%EOF\n"

        appended = b"\n" + obj_bytes + xref + trailer + startxref
        return data + appended

    def extract(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        if not key:
            raise ValueError("Key must be non-empty")

        # Find watermark object (prefer newest)
        matches = list(_WM_OBJ_RE.finditer(data))
        if not matches:
            raise SecretNotFoundError("No WMX watermark object found")
        m = matches[-1]
        length = int(m.group(2))
        stream_pos = m.end()
        stream_bytes = data[stream_pos:stream_pos + length]
        try:
            payload = zlib.decompress(stream_bytes)
        except Exception as e:
            raise SecretNotFoundError("Watermark stream decompression failed") from e

        try:
            rec = json.loads(payload.decode("utf-8"))
            salt = _B64D(rec["salt"])  # type: ignore[index]
            nonce = _B64D(rec["nonce"])  # type: ignore[index]
            ct = _B64D(rec["ct"])       # type: ignore[index]
            mac_hex = rec["mac"]         # type: ignore[index]
            file_hex = rec["file"].lower()
        except Exception as e:
            raise SecretNotFoundError("Corrupt watermark payload") from e

        # Verify MAC
        mac_key = self._kdf("mac:" + key, salt, 32)
        # Compute hash of the original revision (penultimate %%EOF)
        pen_eof = self._penultimate_eof_end(data)
        if pen_eof is None:
            orig_hash = self._sha256(data)
        else:
            orig_hash = self._sha256(data[:pen_eof])

        calc = hmac.new(mac_key, orig_hash + salt + nonce + ct, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calc, mac_hex):
            raise InvalidKeyError("MAC check failed (wrong key or tampered)")

        # Decrypt via XOR-CTR keystream
        enc_key = self._kdf(key, salt, 32)
        ks = self._keystream(enc_key, nonce, len(ct))
        pt = self._xor(ct, ks)

        try:
            return pt.decode("utf-8")
        except UnicodeDecodeError:
            return _B64(pt)
