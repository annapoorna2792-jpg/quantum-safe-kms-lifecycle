"""
Classical cryptography implementations: AES-256-GCM, RSA-4096, ECC-P521.
Uses Python's cryptography library for FIPS-140-2 compliant operations.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class AES256GCM:
    """AES-256-GCM symmetric encryption."""

    KEY_SIZE = 32  # 256 bits

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(AES256GCM.KEY_SIZE)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> dict:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        }

    @staticmethod
    def decrypt(key: bytes, ciphertext_b64: str, nonce_b64: str, associated_data: bytes = b"") -> bytes:
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)


class RSA4096:
    """RSA-4096 asymmetric encryption and signing."""

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Returns (private_key_pem, public_key_pem)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    @staticmethod
    def encrypt(public_key_pem: bytes, plaintext: bytes) -> str:
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(ciphertext).decode()

    @staticmethod
    def decrypt(private_key_pem: bytes, ciphertext_b64: str) -> bytes:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        return private_key.decrypt(
            base64.b64decode(ciphertext_b64),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )


class ECCP521:
    """ECC P-521 key agreement and signing."""

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Returns (private_key_pem, public_key_pem)."""
        private_key = ec.generate_private_key(ec.SECP521R1(), default_backend())
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    @staticmethod
    def sign(private_key_pem: bytes, message: bytes) -> str:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA512()))
        return base64.b64encode(signature).decode()

    @staticmethod
    def verify(public_key_pem: bytes, message: bytes, signature_b64: str) -> bool:
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        try:
            public_key.verify(base64.b64decode(signature_b64), message, ec.ECDSA(hashes.SHA512()))
            return True
        except Exception:
            return False
