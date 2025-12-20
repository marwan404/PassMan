import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto import (
    to_hex,
    from_hex,
    derive_key,
    encrypt_vault_data,
    json_safe,
)


def test_to_from_hex_roundtrip():
    s = b"\x00\x01\x02test"
    assert from_hex(to_hex(s)) == s


def test_derive_key_consistent():
    master = b"password"
    salt = b"\x00" * 16
    k1 = derive_key(master, salt, 1, 8 * 1024, 1, 32)
    k2 = derive_key(master, salt, 1, 8 * 1024, 1, 32)
    assert k1 == k2
    assert len(k1) == 32


def test_encrypt_vault_data_roundtrip():
    key = AESGCM.generate_key(bit_length=256)
    nonce = b"\x00" * 12
    plaintext = b'{"entries": []}\n'
    ciphertext = encrypt_vault_data(key, nonce, plaintext)
    # decrypt using AESGCM directly
    a = AESGCM(key)
    assert a.decrypt(nonce, ciphertext, None) == plaintext


def test_json_safe_bytes():
    data = {"a": b"\x01\x02"}
    safe = json_safe(data)
    # Should be JSON serializable and bytes converted to hex strings
    s = json.dumps(safe)
    assert "01" in s
