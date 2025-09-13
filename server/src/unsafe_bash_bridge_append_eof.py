"""unsafe_bash_bridge_append_eof.py

Toy watermarking method that appends an authenticated payload *after* the
PDF's final EOF marker but by calling a bash command. Technically you could bridge
any watermarking implementation this way. Don't, unless you know how to sanitize user inputs.

"""
from __future__ import annotations

from typing import Final

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
    PdfSource,
)


class UnsafeBashBridgeAppendEOF(WatermarkingMethod):
    """Toy method that appends a watermark record after the PDF EOF.

    """

    name: Final[str] = "bash-bridge-eof"

    # ---------------------
    # Public API overrides
    # ---------------------
    
    @staticmethod
    def get_usage() -> str:
        return "Toy method that appends a watermark record after the PDF EOF. Position and key are ignored."

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a watermark record appended.

        The ``position`` and ``key`` parameters are accepted for API compatibility but
        ignored by this method.
        """
        data = load_pdf_bytes(pdf)
        if not isinstance(secret, str):
            raise ValueError("secret must be a string")
        # Append secret bytes directly after the file content
        out = data + secret.encode("utf-8")
        return out
        
    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        return True
    

    def read_secret(self, pdf, key: str) -> str:
        """Extract the secret if present.
           Prints whatever there is after %EOF
        """
        data = load_pdf_bytes(pdf)
        marker = b"%%EOF"
        idx = data.rfind(marker)
        if idx == -1:
            # No marker; by design of this toy method, return empty string
            return ""
        # If there's a newline after EOF, skip it
        start = idx + len(marker)
        if start < len(data) and data[start:start+1] in (b"\n", b"\r"):
            # handle CRLF or LF
            if data[start:start+2] == b"\r\n":
                start += 2
            else:
                start += 1
        tail = data[start:]
        try:
            return tail.decode("utf-8")
        except Exception:
            # Fallback: replace undecodable bytes
            return tail.decode("utf-8", errors="replace")



__all__ = ["UnsafeBashBridgeAppendEOF"]

