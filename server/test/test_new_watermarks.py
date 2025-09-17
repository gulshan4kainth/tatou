import os
import tempfile

from watermarking_utils import apply_watermark, read_watermark, METHODS


def _round_trip(method: str, secret: str, key: str) -> None:
    pdf_bytes = b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n"
    watermarked = apply_watermark(pdf_bytes, secret=secret, key=key, method=method, position=None)
    assert secret == read_watermark(watermarked, method=method, key=key)


def test_gulshan_round_trip():
    assert 'gulshan' in METHODS
    _round_trip('gulshan', 'secret-g', 'k3y-g')


def test_adam_round_trip():
    assert 'adam' in METHODS
    _round_trip('adam', 'secret-a', 'k3y-a')


def test_psm_round_trip():
    assert 'psm' in METHODS
    _round_trip('psm', 'secret-p', 'k3y-p')
