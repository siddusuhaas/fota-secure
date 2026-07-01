from pathlib import Path

import pytest

from fota_secure import crypto


class TestAesRoundTrip:
    def test_encrypt_decrypt_round_trip(self) -> None:
        key = crypto.generate_aes_key()
        iv = crypto.generate_iv()
        plaintext = b"firmware payload bytes" * 100

        ciphertext = crypto.encrypt_payload(plaintext, key, iv)
        assert ciphertext != plaintext

        assert crypto.decrypt_payload(ciphertext, key, iv) == plaintext

    def test_empty_plaintext_round_trip(self) -> None:
        key = crypto.generate_aes_key()
        iv = crypto.generate_iv()
        ciphertext = crypto.encrypt_payload(b"", key, iv)
        assert crypto.decrypt_payload(ciphertext, key, iv) == b""

    def test_ciphertext_is_block_aligned(self) -> None:
        key = crypto.generate_aes_key()
        iv = crypto.generate_iv()
        ciphertext = crypto.encrypt_payload(b"x", key, iv)
        assert len(ciphertext) % 16 == 0

    def test_decrypt_fails_with_wrong_key(self) -> None:
        key = crypto.generate_aes_key()
        wrong_key = crypto.generate_aes_key()
        iv = crypto.generate_iv()
        ciphertext = crypto.encrypt_payload(b"secret firmware bytes here", key, iv)

        # Wrong key produces garbage padding almost certainly -> unpad raises.
        with pytest.raises(ValueError):
            crypto.decrypt_payload(ciphertext, wrong_key, iv)


class TestKeyAndIvFreshness:
    def test_aes_key_is_32_bytes_and_random_each_call(self) -> None:
        keys = {crypto.generate_aes_key() for _ in range(20)}
        assert all(len(k) == 32 for k in keys)
        assert len(keys) == 20  # no collisions/reuse across calls

    def test_iv_is_16_bytes_and_random_each_call(self) -> None:
        ivs = [crypto.generate_iv() for _ in range(20)]
        assert all(len(iv) == 16 for iv in ivs)
        assert len(set(ivs)) == 20  # every IV distinct
        assert all(iv != b"\x00" * 16 for iv in ivs)  # never all-zero

    def test_encrypting_same_plaintext_twice_gives_different_ciphertext(self) -> None:
        # Fresh IV per build means identical plaintext must not produce
        # identical ciphertext across builds (docs/THREAT_MODEL.md item 4).
        key = crypto.generate_aes_key()
        plaintext = b"identical firmware bytes across two builds"
        ct1 = crypto.encrypt_payload(plaintext, key, crypto.generate_iv())
        ct2 = crypto.encrypt_payload(plaintext, key, crypto.generate_iv())
        assert ct1 != ct2


class TestRsaWrapUnwrap:
    def test_wrap_unwrap_round_trip_with_real_keygen_output(
        self, real_keypairs: Path
    ) -> None:
        device_public = crypto.load_public_key(real_keypairs / "device_public.pem")
        device_private = crypto.load_private_key(real_keypairs / "device_private.pem")

        aes_key = crypto.generate_aes_key()
        wrapped = crypto.wrap_key(aes_key, device_public)
        assert wrapped != aes_key

        assert crypto.unwrap_key(wrapped, device_private) == aes_key

    def test_unwrap_fails_with_wrong_private_key(self, real_keypairs: Path) -> None:
        device_public = crypto.load_public_key(real_keypairs / "device_public.pem")
        # signing_private is a *different* keypair generated in the same
        # run - a realistic "wrong key" rather than an ad hoc stand-in.
        wrong_private = crypto.load_private_key(real_keypairs / "signing_private.pem")

        wrapped = crypto.wrap_key(crypto.generate_aes_key(), device_public)

        with pytest.raises(ValueError):
            crypto.unwrap_key(wrapped, wrong_private)


class TestSignVerify:
    def test_sign_verify_round_trip_with_real_keygen_output(
        self, real_keypairs: Path
    ) -> None:
        signing_private = crypto.load_private_key(
            real_keypairs / "signing_private.pem"
        )
        signing_public = crypto.load_public_key(real_keypairs / "signing_public.pem")

        data = b"fixed_header || wrapped_key || ciphertext_payload"
        signature = crypto.sign(data, signing_private)
        assert len(signature) == 256  # RSA-2048 signature size

        assert crypto.verify_signature(data, signature, signing_public) is True

    def test_verify_fails_on_tampered_ciphertext_byte(
        self, real_keypairs: Path
    ) -> None:
        signing_private = crypto.load_private_key(
            real_keypairs / "signing_private.pem"
        )
        signing_public = crypto.load_public_key(real_keypairs / "signing_public.pem")

        header = b"HEADER00"
        wrapped_key = b"WRAPPEDKEY"
        ciphertext = bytearray(b"original ciphertext payload bytes")
        signature = crypto.sign(header + wrapped_key + bytes(ciphertext), signing_private)

        ciphertext[0] ^= 0xFF  # flip a single byte
        tampered = header + wrapped_key + bytes(ciphertext)

        assert crypto.verify_signature(tampered, signature, signing_public) is False

    def test_verify_fails_on_tampered_header(self, real_keypairs: Path) -> None:
        signing_private = crypto.load_private_key(
            real_keypairs / "signing_private.pem"
        )
        signing_public = crypto.load_public_key(real_keypairs / "signing_public.pem")

        data = b"HEADER00" + b"WRAPPEDKEY" + b"ciphertext payload bytes"
        signature = crypto.sign(data, signing_private)

        tampered = b"HEADER01" + b"WRAPPEDKEY" + b"ciphertext payload bytes"
        assert crypto.verify_signature(tampered, signature, signing_public) is False

    def test_verify_fails_with_wrong_public_key(self, real_keypairs: Path) -> None:
        signing_private = crypto.load_private_key(
            real_keypairs / "signing_private.pem"
        )
        # device_public is a different keypair from the same keygen run.
        wrong_public = crypto.load_public_key(real_keypairs / "device_public.pem")

        data = b"some signed data"
        signature = crypto.sign(data, signing_private)

        assert crypto.verify_signature(data, signature, wrong_public) is False
