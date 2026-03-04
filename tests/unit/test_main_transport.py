"""Tests for CLI transport normalization in __main__."""

import argparse

import pytest

from rootly_mcp_server.__main__ import normalize_transport


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("stdio", "stdio"),
        ("sse", "sse"),
        ("streamable-http", "streamable-http"),
        ("streamable", "streamable-http"),
        ("http", "streamable-http"),
        ("both", "both"),
        ("dual", "both"),
        ("dual-http", "both"),
        ("streamable+sse", "both"),
        ("sse+streamable", "both"),
    ],
)
def test_normalize_transport_supported_aliases(value: str, expected: str):
    assert normalize_transport(value) == expected


def test_normalize_transport_rejects_invalid_value():
    with pytest.raises(argparse.ArgumentTypeError):
        normalize_transport("invalid-transport")
