from __future__ import annotations
from typing import Final

from watermarking_method import (
    WatermarkingMethod,
    load_pdf_bytes,
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
)

class CommentWatermark(WatermarkingMethod):
    """Adds a watermark as a PDF comment inside the PDF."""

    name: Final[str] = "comment-watermark"

    @staticmethod
    def get_usage() -> str:
        return "Adds a watermark as a PDF comment: %% Watermark: SECRET"

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Return a new PDF with a comment watermark added."""
        data = load_pdf_bytes(pdf)
        
        # Insert the watermark comment before the EOF
        eof_index = data.rfind(b"%%EOF")
        if eof_index == -1:
            raise WatermarkingError("PDF missing EOF marker")
        
        watermark_comment = f"\n% Watermark: {secret}\n".encode("utf-8")
        new_pdf = data[:eof_index] + watermark_comment + data[eof_index:]
        return new_pdf

    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:
        return True

    def read_secret(self, pdf, key: str) -> str:
        """Extract the watermark comment if present."""
        data = load_pdf_bytes(pdf)
        import re

        match = re.search(b"% Watermark: (.+?)\r?\n", data)
        if not match:
            raise SecretNotFoundError("No watermark found")
        return match.group(1).decode("utf-8")


__all__ = ["CommentWatermark"]
