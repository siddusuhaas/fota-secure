"""Pack/unpack the fixed header and assemble/parse the full update blob.

See docs/FORMAT_SPEC.md for the authoritative on-disk layout — packager
and consumer must agree on this byte-for-byte.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = b"FOTS"
FORMAT_VERSION = 0x01

PLATFORM_TAG_SIZE = 16
FW_VERSION_SIZE = 12
IV_SIZE = 16
SIGNATURE_SIZE = 256

# '!' = big-endian, standard sizes, no implicit padding (docs/FORMAT_SPEC.md
# is explicit that fields are packed back-to-back).
_HEADER_STRUCT = struct.Struct("!4sB16s12sH16s")
HEADER_SIZE = _HEADER_STRUCT.size  # 51 bytes


class BlobFormatError(ValueError):
    """Raised when a header or blob is malformed, truncated, or otherwise
    fails to parse per docs/FORMAT_SPEC.md."""


@dataclass(frozen=True)
class Header:
    platform_tag: str
    fw_version: str
    wrapped_key_len: int
    iv: bytes


@dataclass(frozen=True)
class ParsedBlob:
    header: Header
    wrapped_key: bytes
    signature: bytes
    payload: bytes
    # header || wrapped_key || payload - the exact bytes the signature
    # covers per docs/FORMAT_SPEC.md's Signature Section.
    signed_data: bytes


def _pack_ascii_field(value: str, size: int, field_name: str) -> bytes:
    encoded = value.encode("ascii")
    if len(encoded) > size:
        raise BlobFormatError(
            f"{field_name} {value!r} is {len(encoded)} bytes, exceeds max {size}"
        )
    return encoded.ljust(size, b"\x00")


def build_header(
    platform_tag: str, fw_version: str, iv: bytes, wrapped_key_len: int
) -> bytes:
    """Pack the fixed header per docs/FORMAT_SPEC.md."""
    if len(iv) != IV_SIZE:
        raise BlobFormatError(f"iv must be {IV_SIZE} bytes, got {len(iv)}")
    if not (0 <= wrapped_key_len <= 0xFFFF):
        raise BlobFormatError(f"wrapped_key_len {wrapped_key_len} out of uint16 range")

    return _HEADER_STRUCT.pack(
        MAGIC,
        FORMAT_VERSION,
        _pack_ascii_field(platform_tag, PLATFORM_TAG_SIZE, "platform_tag"),
        _pack_ascii_field(fw_version, FW_VERSION_SIZE, "fw_version"),
        wrapped_key_len,
        iv,
    )


def parse_header(data: bytes) -> Header:
    """Unpack and validate the fixed header.

    Raises BlobFormatError on any malformed/truncated input rather than
    crashing or returning garbage.
    """
    if len(data) < HEADER_SIZE:
        raise BlobFormatError(
            f"header truncated: need {HEADER_SIZE} bytes, got {len(data)}"
        )

    magic, format_version, platform_tag_raw, fw_version_raw, wrapped_key_len, iv = (
        _HEADER_STRUCT.unpack(data[:HEADER_SIZE])
    )

    if magic != MAGIC:
        raise BlobFormatError(f"bad magic: expected {MAGIC!r}, got {magic!r}")
    if format_version != FORMAT_VERSION:
        raise BlobFormatError(
            "unsupported format_version: expected "
            f"{FORMAT_VERSION}, got {format_version}"
        )

    return Header(
        platform_tag=platform_tag_raw.rstrip(b"\x00").decode("ascii"),
        fw_version=fw_version_raw.rstrip(b"\x00").decode("ascii"),
        wrapped_key_len=wrapped_key_len,
        iv=iv,
    )


def assemble(
    header: bytes, wrapped_key: bytes, signature: bytes, payload: bytes
) -> bytes:
    """Concatenate the four sections into the final blob: header ||
    wrapped_key || signature || payload, per docs/FORMAT_SPEC.md."""
    if len(header) != HEADER_SIZE:
        raise BlobFormatError(f"header must be {HEADER_SIZE} bytes, got {len(header)}")
    if len(signature) != SIGNATURE_SIZE:
        raise BlobFormatError(
            f"signature must be {SIGNATURE_SIZE} bytes, got {len(signature)}"
        )
    return header + wrapped_key + signature + payload


def parse_blob(data: bytes) -> ParsedBlob:
    """Split a full blob into its sections.

    Raises BlobFormatError on any truncation rather than reading past the
    end of the buffer or returning partial/garbage sections.
    """
    header = parse_header(data)
    raw_header = data[:HEADER_SIZE]

    wrapped_key_end = HEADER_SIZE + header.wrapped_key_len
    signature_end = wrapped_key_end + SIGNATURE_SIZE
    if len(data) < signature_end:
        raise BlobFormatError(
            f"blob truncated: need at least {signature_end} bytes "
            f"(header + wrapped_key + signature), got {len(data)}"
        )

    wrapped_key = data[HEADER_SIZE:wrapped_key_end]
    signature = data[wrapped_key_end:signature_end]
    payload = data[signature_end:]

    return ParsedBlob(
        header=header,
        wrapped_key=wrapped_key,
        signature=signature,
        payload=payload,
        signed_data=raw_header + wrapped_key + payload,
    )
