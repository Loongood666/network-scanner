"""
AES-256-GCM encryption utilities for secure photo backup transmission.
Uses RSA-2048 for key exchange and AES-256-GCM for bulk encryption.
"""

import os
import json
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# RSA Key Management
# ---------------------------------------------------------------------------

SERVER_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwWxHSGpoBXhcGUzJDoDV
vCJzORB8QFSmVVFGVhBYmXzCTARhDSNMBASiFMBSVLGIpLmPPwEOHgEEiHEpFNQa
lc9XLprgVjHRxCESEELHSMMJZSmnAVNQPFCGpGKMHwTxoSoGAqFPvLSDInFqCKPE
LPqHMoIFNfHlSHBKNRmhDDiFKGBPKKFiCOBpCAEjlhGYDsOHMPhxSsKKDqIHoHgL
nLJGDEgSfxNGCqmQRqLPFhJLiJRHEIVWOJOoFJKGCYMVnFmMUDnAJkOPPJtJLKGX
AGDCiCqXCIJFGnITSkIqJNOHYEDGJDoweLhDDIIYEoKuPtJEKioMJElMKYcHqKRr
nQIDAQAB
-----END PUBLIC KEY-----"""


def generate_rsa_keypair():
    """Generate a fresh RSA-2048 key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def load_server_public_key(pem_str=None):
    """Load server's RSA public key from PEM string."""
    pem = pem_str or SERVER_PUBLIC_KEY_PEM
    return serialization.load_pem_public_key(pem.encode(), backend=default_backend())


def encrypt_session_key(session_key, server_public_key):
    """Encrypt AES session key using RSA-OAEP."""
    return server_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_session_key(encrypted_key, private_key):
    """Decrypt AES session key using RSA private key."""
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# AES-256-GCM Encryption
# ---------------------------------------------------------------------------

def generate_aes_key():
    """Generate a random 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


def generate_nonce():
    """Generate a random 96-bit nonce for AES-GCM."""
    return os.urandom(12)


def encrypt_data(plaintext, key, associated_data=b""):
    """Encrypt data with AES-256-GCM. Returns (nonce + ciphertext + tag)."""
    aesgcm = AESGCM(key)
    nonce = generate_nonce()
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    # Prepend nonce to ciphertext (ciphertext already includes 16-byte tag at end)
    return nonce + ciphertext


def decrypt_data(encrypted_blob, key, associated_data=b""):
    """Decrypt AES-256-GCM encrypted blob."""
    aesgcm = AESGCM(key)
    nonce = encrypted_blob[:12]
    ciphertext = encrypted_blob[12:]
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


# ---------------------------------------------------------------------------
# File encryption helpers
# ---------------------------------------------------------------------------

def encrypt_file(filepath, aes_key):
    """Encrypt a file on disk. Returns the encrypted bytes."""
    with open(filepath, "rb") as f:
        data = f.read()
    filename = os.path.basename(filepath).encode("utf-8")
    associated_data = hashlib.sha256(filename).digest()
    return encrypt_data(data, aes_key, associated_data)


def decrypt_file(encrypted_blob, filename, aes_key):
    """Decrypt file bytes and return plaintext."""
    associated_data = hashlib.sha256(filename.encode("utf-8")).digest()
    return decrypt_data(encrypted_blob, aes_key, associated_data)


# ---------------------------------------------------------------------------
# Transmission protocol helpers
# ---------------------------------------------------------------------------

def encrypt_transmission(encrypted_blob, server_pubkey):
    """
    Full transmission encryption:
    1. Generate random AES session key
    2. Encrypt payload with AES-256-GCM
    3. Encrypt AES key with RSA-OAEP
    Returns (encrypted_aes_key, encrypted_payload)
    """
    session_key = generate_aes_key()
    encrypted_aes_key = encrypt_session_key(session_key, server_pubkey)
    encrypted_payload = encrypt_data(encrypted_blob, session_key)
    return encrypted_aes_key, encrypted_payload


def decrypt_transmission(encrypted_aes_key, encrypted_payload, private_key):
    """
    Decrypt incoming transmission:
    1. Decrypt AES session key with RSA private key
    2. Decrypt payload with AES-256-GCM
    Returns plaintext bytes
    """
    session_key = decrypt_session_key(encrypted_aes_key, private_key)
    return decrypt_data(encrypted_payload, session_key)