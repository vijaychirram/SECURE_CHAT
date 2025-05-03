import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_salt() -> bytes:
    """
    Generate a new 16‑byte salt for PBKDF2.
    Store or share this salt so both sides use the same.
    """
    return os.urandom(16)

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive a 256‑bit AES key from the passphrase and salt using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,            # 256 bits
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def encrypt_message(key: bytes, plaintext: str) -> bytes:
    """
    Encrypt plaintext under AES‑CBC with a random IV. 
    Returns IV || ciphertext.
    """
    iv = os.urandom(16)
    # PKCS7 pad to AES block size (128 bits)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext

def decrypt_message(key: bytes, iv_ciphertext: bytes) -> str:
    """
    Given IV || ciphertext, decrypt with AES‑CBC and strip PKCS7 padding.
    Returns the original plaintext.
    """
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()

    return data.decode()

# ----- at the bottom of crypto_utils.py -----
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

# 1. Generate DH parameters once (you can serialize & reuse these)
DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_dh_keypair():
    """
    Create a new DH private/public key pair.
    Returns (private_key, public_bytes).
    """
    priv = DH_PARAMETERS.generate_private_key()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub

def derive_dh_shared_key(priv, peer_pub_bytes):
    """
    Given your DH private key and the peer's public bytes,
    compute a shared secret and then HKDF‑SHA256 it into a fresh 32‑byte key.
    """
    peer_pub = serialization.load_pem_public_key(peer_pub_bytes, backend=default_backend())
    shared_secret = priv.exchange(peer_pub)
    # Derive a symmetric key via HKDF:
    new_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=None, info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    return new_key

