#!/usr/bin/env python3

# Copyright (c) 2015-2020 Clearmatics Technologies Ltd
#
# SPDX-License-Identifier: LGPL-3.0+

"""
Encryption operations for Zeth notes. Supports an `encrypt` operation using
receivers public key, and a `decrypt` operation using the corresponding private
key. `decrypt` fails (except with negligible probability) if the ciphertext was
encrypted with a different public key.

This implementation makes use of the `cryptography` library with OpenSSL
backend. For the avoidance of doubt, the implementation adheres to the
appropriate standards as follows. (links refer to specific versions of external
libraries, to ensure that line numbers are correct, but the descriptions are
expected to hold for all versions.)

As described in [Bernstein06], private keys may be generated as 32 random bytes
with bits 0, 1 and 2 of the first byte cleared, bit 7 of the last byte cleared,
and bit 6 of the last byte set. This happens at key generation time. See:

  https://github.com/openssl/openssl/blob/be9d82bb35812ac65cd92316d1ae7c7c75efe9cf/crypto/ec/ecx_meth.c#L81

[LangleyN18] describes Poly1305, including the requirement that the "r" value of
the key (r, s) be "clamped". Note that this clamping is carried out by the
cryptography library when the key is generated. See:

  https://github.com/openssl/openssl/blob/master/crypto/poly1305/poly1305.c#L143

The specification of the ChaCha20 stream cipher in [LangleyN18] (page 10)
describes the inputs to the encryption functions as a 256-bit key, a 32-bit
counter and a 96-bit nonce. This differs slightly from the signature of the
encryption function in the cryptography library, which accepts a 256-bit key and
128-bit nonce.  That is, no counter is mentioned leaving ambiguity as to whether
this data is processed exactly as described in [LangleyN18]. Internally, the
cryptography library treats the first 32-bit word of the nonce as a counter and
increments this as necessary in accordance with [LangleyN18]. See:

  https://github.com/openssl/openssl/blob/be9d82bb35812ac65cd92316d1ae7c7c75efe9cf/crypto/chacha/chacha_enc.c#L128
  https://github.com/openssl/openssl/blob/be9d82bb35812ac65cd92316d1ae7c7c75efe9cf/crypto/evp/e_chacha20_poly1305.c#L95

References:

\\[Bernstein06]
 "Curve25519:new Diffie-Hellman speed records"
 Daniel J. Bernstein,
 International Workshop on Public Key Cryptography, 2006,
 <https://cr.yp.to/ecdh/curve25519-20060209.pdf>

\\[LangleyN18]
 "Chacha20 and poly1305 for ietf protocols."
 Adam Langley and Yoav Nir,
 RFC 8439, 2018,
 <https://tools.ietf.org/html/rfc8439>
"""

from typing import NewType

from zeth.constants import KDF_TAG, EC_PUBLIC_KEY_LENGTH, SYM_KEY_LENGTH,\
    NOTE_LENGTH, TAG_LENGTH, SYM_NONCE_VALUE, SYM_NONCE_LENGTH,\
    ENCRYPTED_NOTE_LENGTH
from zeth.utils import bits_to_bytes_len

from cryptography.hazmat.primitives.asymmetric.x25519 \
    import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, poly1305
from cryptography.hazmat.primitives.serialization import \
    Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.exceptions import InvalidSignature \
    as cryptography_InvalidSignature


# Encryption constants byte length
_PK_BYTE_LENGTH = bits_to_bytes_len(EC_PUBLIC_KEY_LENGTH)
_SYM_KEY_BYTE_LENGTH = bits_to_bytes_len(SYM_KEY_LENGTH)
_SYM_NONCE_BYTE_LENGTH = bits_to_bytes_len(SYM_NONCE_LENGTH)
_NOTE_BYTE_LENGTH = bits_to_bytes_len(NOTE_LENGTH)
_TAG_BYTE_LENGTH = bits_to_bytes_len(TAG_LENGTH)
_ENCRYPTED_NOTE_BYTE_LENGTH = bits_to_bytes_len(ENCRYPTED_NOTE_LENGTH)

# Expose the exception type
InvalidSignature = cryptography_InvalidSignature

# Represents a secret key for encryption
EncryptionSecretKey = NewType('EncryptionSecretKey', object)


def generate_encryption_secret_key() -> EncryptionSecretKey:
    return EncryptionSecretKey(X25519PrivateKey.generate())  # type: ignore


def encode_encryption_secret_key(sk: EncryptionSecretKey) -> bytes:
    return sk.private_bytes(  # type: ignore
        Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def decode_encryption_secret_key(sk_bytes: bytes) -> EncryptionSecretKey:
    return EncryptionSecretKey(
        X25519PrivateKey.from_private_bytes(sk_bytes))


def encryption_secret_key_as_hex(sk: EncryptionSecretKey) -> str:
    return encode_encryption_secret_key(sk).hex()  # type: ignore


def encryption_secret_key_from_hex(pk_str: str) -> EncryptionSecretKey:
    return EncryptionSecretKey(
        X25519PrivateKey.from_private_bytes(bytes.fromhex(pk_str)))


# Public key for decryption
EncryptionPublicKey = NewType('EncryptionPublicKey', object)


def get_encryption_public_key(
        enc_secret: EncryptionSecretKey) -> EncryptionPublicKey:
    return enc_secret.public_key()  # type: ignore


def encode_encryption_public_key(pk: EncryptionPublicKey) -> bytes:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)  # type: ignore


def decode_encryption_public_key(pk_data: bytes) -> EncryptionPublicKey:
    return EncryptionPublicKey(X25519PublicKey.from_public_bytes(pk_data))


def encryption_public_key_as_hex(pk: EncryptionPublicKey) -> str:
    return encode_encryption_public_key(pk).hex()


def encryption_public_key_from_hex(pk_str: str) -> EncryptionPublicKey:
    return decode_encryption_public_key(bytes.fromhex(pk_str))


class EncryptionKeyPair:
    """
    Key-pair for encrypting joinsplit notes.
    """
    def __init__(self, k_sk: EncryptionSecretKey, k_pk: EncryptionPublicKey):
        self.k_pk: EncryptionPublicKey = k_pk
        self.k_sk: EncryptionSecretKey = k_sk


def generate_encryption_keypair() -> EncryptionKeyPair:
    sk = generate_encryption_secret_key()
    return EncryptionKeyPair(sk, get_encryption_public_key(sk))


def encrypt(message: bytes, pk_receiver: EncryptionPublicKey) -> bytes:
    """
    Encrypts a string message under a ec25519 public key
    by using a custom dhaes-based scheme.
    See: https://eprint.iacr.org/1999/007
    """
    assert \
        len(message) == _NOTE_BYTE_LENGTH, \
        f"expected message length {_NOTE_BYTE_LENGTH}, saw {len(message)}"

    # Generate ephemeral keypair
    eph_keypair = generate_encryption_keypair()

    # Compute shared secret and eph key
    shared_key = _exchange(eph_keypair.k_sk, pk_receiver)
    pk_sender_bytes = encode_encryption_public_key(eph_keypair.k_pk)

    # Generate key material
    key_material = _kdf(pk_sender_bytes, shared_key)

    # Generate symmetric ciphertext
    # Chacha encryption
    sym_key = key_material[:_PK_BYTE_LENGTH]
    mac_key = key_material[_PK_BYTE_LENGTH:]
    nonce = (SYM_NONCE_VALUE).to_bytes(_SYM_NONCE_BYTE_LENGTH, byteorder='little')
    algorithm = algorithms.ChaCha20(sym_key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    sym_ciphertext = encryptor.update(message)

    # Generate mac
    mac = poly1305.Poly1305(mac_key)
    mac.update(sym_ciphertext)
    tag = mac.finalize()

    # Arrange ciphertext
    return pk_sender_bytes+sym_ciphertext+tag


def decrypt(
        encrypted_message: bytes,
        sk_receiver: EncryptionSecretKey) -> bytes:
    """
    Decrypts a NOTE_LENGTH-byte message by using valid ec25519 private key
    objects.  See: https://pynacl.readthedocs.io/en/stable/public/
    """
    assert \
        len(encrypted_message) == _ENCRYPTED_NOTE_BYTE_LENGTH, \
        "encrypted_message byte-length must be: "+str(_ENCRYPTED_NOTE_BYTE_LENGTH)

    assert(isinstance(sk_receiver, X25519PrivateKey)), \
        f"PrivateKey: {sk_receiver} ({type(sk_receiver)})"

    # Compute shared secret
    pk_sender_bytes = encrypted_message[:_PK_BYTE_LENGTH]
    pk_sender = decode_encryption_public_key(pk_sender_bytes)
    shared_key = _exchange(sk_receiver, pk_sender)

    # Generate key material and recover keys
    key_material = _kdf(pk_sender_bytes, shared_key)
    sym_key = key_material[:_SYM_KEY_BYTE_LENGTH]
    mac_key = key_material[_SYM_KEY_BYTE_LENGTH:]

    # ct_sym and mac
    ct_sym = encrypted_message[
        _PK_BYTE_LENGTH:
        _PK_BYTE_LENGTH + _NOTE_BYTE_LENGTH]
    tag = encrypted_message[
        _PK_BYTE_LENGTH + _NOTE_BYTE_LENGTH:
        _PK_BYTE_LENGTH + _NOTE_BYTE_LENGTH + _TAG_BYTE_LENGTH]

    # Verify the mac
    mac = poly1305.Poly1305(mac_key)
    mac.update(ct_sym)
    mac.verify(tag)

    # Decrypt sym ciphertext
    nonce = (SYM_NONCE_VALUE).to_bytes(_SYM_NONCE_BYTE_LENGTH, byteorder='little')
    algorithm = algorithms.ChaCha20(sym_key, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(ct_sym)

    return message


def _exchange(sk: EncryptionSecretKey, pk: EncryptionPublicKey) -> bytes:
    return sk.exchange(pk)  # type: ignore


def _kdf(eph_pk: bytes, shared_key: bytes) -> bytes:
    """
    Key derivation function
    """
    # Hashing
    key_material = hashes.Hash(
        hashes.BLAKE2b(64),
        backend=default_backend())
    key_material.update(KDF_TAG)
    key_material.update(eph_pk)
    key_material.update(shared_key)
    digest = key_material.finalize()

    return digest