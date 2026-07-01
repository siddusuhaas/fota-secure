import os
from pathlib import Path

import pytest

from fota_secure import blob, crypto


class TestHeaderRoundTrip:
    def test_pack_unpack_basic(self) -> None:
        iv = crypto.generate_iv()
        header_bytes = blob.build_header(
            platform_tag="GENERIC", fw_version="1.0.0.0", iv=iv, wrapped_key_len=256
        )
        assert len(header_bytes) == blob.HEADER_SIZE == 51

        header = blob.parse_header(header_bytes)
        assert header.platform_tag == "GENERIC"
        assert header.fw_version == "1.0.0.0"
        assert header.wrapped_key_len == 256
        assert header.iv == iv

    def test_pack_unpack_platform_tag_at_max_length(self) -> None:
        # Exactly 16 ASCII bytes - no room for a NUL terminator, must not
        # be silently truncated and must round-trip exactly.
        tag = "GENERIC_DEVICE01"
        assert len(tag) == blob.PLATFORM_TAG_SIZE

        header_bytes = blob.build_header(
            platform_tag=tag,
            fw_version="1.0.0.0",
            iv=crypto.generate_iv(),
            wrapped_key_len=256,
        )
        header = blob.parse_header(header_bytes)
        assert header.platform_tag == tag

    def test_pack_unpack_fw_version_at_max_length(self) -> None:
        # Exactly 12 ASCII bytes.
        version = "123.45.6.789"
        assert len(version) == blob.FW_VERSION_SIZE

        header_bytes = blob.build_header(
            platform_tag="GENERIC",
            fw_version=version,
            iv=crypto.generate_iv(),
            wrapped_key_len=256,
        )
        header = blob.parse_header(header_bytes)
        assert header.fw_version == version

    def test_platform_tag_over_max_length_raises(self) -> None:
        with pytest.raises(blob.BlobFormatError):
            blob.build_header(
                platform_tag="A" * (blob.PLATFORM_TAG_SIZE + 1),
                fw_version="1.0.0.0",
                iv=crypto.generate_iv(),
                wrapped_key_len=256,
            )

    def test_fw_version_over_max_length_raises(self) -> None:
        with pytest.raises(blob.BlobFormatError):
            blob.build_header(
                platform_tag="GENERIC",
                fw_version="1" * (blob.FW_VERSION_SIZE + 1),
                iv=crypto.generate_iv(),
                wrapped_key_len=256,
            )

    def test_bad_iv_length_raises(self) -> None:
        with pytest.raises(blob.BlobFormatError):
            blob.build_header(
                platform_tag="GENERIC",
                fw_version="1.0.0.0",
                iv=b"\x00" * 8,
                wrapped_key_len=256,
            )


class TestHeaderMalformedInput:
    def test_truncated_header_raises_cleanly(self) -> None:
        full = blob.build_header(
            platform_tag="GENERIC",
            fw_version="1.0.0.0",
            iv=crypto.generate_iv(),
            wrapped_key_len=256,
        )
        for cut in (0, 1, 10, blob.HEADER_SIZE - 1):
            with pytest.raises(blob.BlobFormatError):
                blob.parse_header(full[:cut])

    def test_bad_magic_raises_cleanly(self) -> None:
        full = bytearray(
            blob.build_header(
                platform_tag="GENERIC",
                fw_version="1.0.0.0",
                iv=crypto.generate_iv(),
                wrapped_key_len=256,
            )
        )
        full[0:4] = b"XXXX"
        with pytest.raises(blob.BlobFormatError):
            blob.parse_header(bytes(full))

    def test_bad_format_version_raises_cleanly(self) -> None:
        full = bytearray(
            blob.build_header(
                platform_tag="GENERIC",
                fw_version="1.0.0.0",
                iv=crypto.generate_iv(),
                wrapped_key_len=256,
            )
        )
        full[4] = 0xFF
        with pytest.raises(blob.BlobFormatError):
            blob.parse_header(bytes(full))


class TestBlobAssembleParse:
    def test_assemble_parse_round_trip(self) -> None:
        header_bytes = blob.build_header(
            platform_tag="GENERIC",
            fw_version="1.0.0.0",
            iv=crypto.generate_iv(),
            wrapped_key_len=32,
        )
        wrapped_key = os.urandom(32)
        signature = os.urandom(blob.SIGNATURE_SIZE)
        payload = os.urandom(128)

        full_blob = blob.assemble(header_bytes, wrapped_key, signature, payload)
        parsed = blob.parse_blob(full_blob)

        assert parsed.header.platform_tag == "GENERIC"
        assert parsed.wrapped_key == wrapped_key
        assert parsed.signature == signature
        assert parsed.payload == payload
        assert parsed.signed_data == header_bytes + wrapped_key + payload

    def test_truncated_blob_missing_signature_bytes_raises_cleanly(self) -> None:
        header_bytes = blob.build_header(
            platform_tag="GENERIC",
            fw_version="1.0.0.0",
            iv=crypto.generate_iv(),
            wrapped_key_len=32,
        )
        wrapped_key = os.urandom(32)
        signature = os.urandom(blob.SIGNATURE_SIZE)
        payload = os.urandom(128)
        full_blob = blob.assemble(header_bytes, wrapped_key, signature, payload)

        # Chop off the last byte of the signature section (still "has" a
        # payload section length-wise, so this must be caught by the
        # explicit length check, not accidentally parse as a short payload).
        truncated = full_blob[: -(len(payload) + 1)]
        with pytest.raises(blob.BlobFormatError):
            blob.parse_blob(truncated)

    def test_truncated_blob_missing_wrapped_key_raises_cleanly(self) -> None:
        header_bytes = blob.build_header(
            platform_tag="GENERIC",
            fw_version="1.0.0.0",
            iv=crypto.generate_iv(),
            wrapped_key_len=32,
        )
        # Only the header, none of wrapped_key/signature/payload.
        with pytest.raises(blob.BlobFormatError):
            blob.parse_blob(header_bytes)

    def test_empty_input_raises_cleanly(self) -> None:
        with pytest.raises(blob.BlobFormatError):
            blob.parse_blob(b"")

    def test_assemble_rejects_wrong_size_header(self) -> None:
        with pytest.raises(blob.BlobFormatError):
            blob.assemble(b"short", os.urandom(32), os.urandom(blob.SIGNATURE_SIZE), b"")

    def test_assemble_rejects_wrong_size_signature(self) -> None:
        header_bytes = blob.build_header(
            platform_tag="GENERIC",
            fw_version="1.0.0.0",
            iv=crypto.generate_iv(),
            wrapped_key_len=32,
        )
        with pytest.raises(blob.BlobFormatError):
            blob.assemble(header_bytes, os.urandom(32), b"short-sig", b"")


class TestSignatureCoversFullPackage:
    """docs/THREAT_MODEL.md item 6: the signature binds header, wrapped_key,
    and ciphertext together so nothing can be swapped between two otherwise
    validly-signed packages."""

    def test_signature_does_not_verify_against_a_different_header(
        self, real_keypairs: Path
    ) -> None:
        signing_private = crypto.load_private_key(
            real_keypairs / "signing_private.pem"
        )
        signing_public = crypto.load_public_key(real_keypairs / "signing_public.pem")

        wrapped_key = os.urandom(256)
        payload = os.urandom(128)

        header_a = blob.build_header(
            platform_tag="GENERIC",
            fw_version="1.0.0.0",
            iv=crypto.generate_iv(),
            wrapped_key_len=len(wrapped_key),
        )
        header_b = blob.build_header(
            platform_tag="GENERIC",
            fw_version="2.0.0.0",  # only the header differs
            iv=crypto.generate_iv(),
            wrapped_key_len=len(wrapped_key),
        )

        signature_a = crypto.sign(header_a + wrapped_key + payload, signing_private)

        # If the signature only covered the ciphertext, this would verify.
        # It must not, since header_a != header_b.
        assert (
            crypto.verify_signature(
                header_b + wrapped_key + payload, signature_a, signing_public
            )
            is False
        )
        # Sanity check: the same signature does verify against the original
        # header it was actually computed over.
        assert (
            crypto.verify_signature(
                header_a + wrapped_key + payload, signature_a, signing_public
            )
            is True
        )

    def test_mix_and_match_wrapped_key_swap_fails_verification(
        self, real_keypairs: Path
    ) -> None:
        """Simulates docs/THREAT_MODEL.md item 6's attack directly: build
        two independently valid, signed blobs, then splice blob 1's
        wrapped_key into blob 2 while keeping blob 2's own header and
        signature. The forged blob must fail signature verification.
        """
        signing_private = crypto.load_private_key(
            real_keypairs / "signing_private.pem"
        )
        signing_public = crypto.load_public_key(real_keypairs / "signing_public.pem")
        device_public = crypto.load_public_key(real_keypairs / "device_public.pem")
        device_private = crypto.load_private_key(real_keypairs / "device_private.pem")

        # Two distinct, legitimately-signed releases.
        aes_key_1 = crypto.generate_aes_key()
        wrapped_key_1 = crypto.wrap_key(aes_key_1, device_public)
        payload_1 = os.urandom(96)
        header_1 = blob.build_header(
            platform_tag="GENERIC",
            fw_version="1.0.0.0",
            iv=crypto.generate_iv(),
            wrapped_key_len=len(wrapped_key_1),
        )
        signature_1 = crypto.sign(
            header_1 + wrapped_key_1 + payload_1, signing_private
        )
        blob_1 = blob.assemble(header_1, wrapped_key_1, signature_1, payload_1)

        aes_key_2 = crypto.generate_aes_key()
        wrapped_key_2 = crypto.wrap_key(aes_key_2, device_public)
        payload_2 = os.urandom(96)
        header_2 = blob.build_header(
            platform_tag="GENERIC",
            fw_version="2.0.0.0",
            iv=crypto.generate_iv(),
            wrapped_key_len=len(wrapped_key_2),
        )
        signature_2 = crypto.sign(
            header_2 + wrapped_key_2 + payload_2, signing_private
        )
        blob_2 = blob.assemble(header_2, wrapped_key_2, signature_2, payload_2)

        # Both individually verify - these are two genuinely valid packages.
        parsed_1 = blob.parse_blob(blob_1)
        parsed_2 = blob.parse_blob(blob_2)
        assert (
            crypto.verify_signature(
                parsed_1.signed_data, parsed_1.signature, signing_public
            )
            is True
        )
        assert (
            crypto.verify_signature(
                parsed_2.signed_data, parsed_2.signature, signing_public
            )
            is True
        )
        # RSA-OAEP output size only depends on key size, so wrapped_key_1
        # and wrapped_key_2 are the same length - the swap below produces
        # a structurally well-formed (parseable) blob, not just a
        # truncated/corrupt one, isolating the test to the signature check.
        assert len(wrapped_key_1) == len(wrapped_key_2)

        # Attacker: take blob 2's header + signature, but splice in blob 1's
        # wrapped_key, keeping blob 2's own payload.
        forged_blob = blob.assemble(header_2, wrapped_key_1, signature_2, payload_2)
        forged = blob.parse_blob(forged_blob)

        assert (
            crypto.verify_signature(forged.signed_data, forged.signature, signing_public)
            is False
        )

        # And to be thorough: the swapped-in wrapped_key still unwraps to
        # aes_key_1 under the device's real private key - proving the
        # attack would have handed the device a *different* AES key than
        # the one that was ever validly bound to header_2/payload_2, had
        # signature verification not caught it first.
        assert crypto.unwrap_key(forged.wrapped_key, device_private) == aes_key_1
