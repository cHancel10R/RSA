"""RSA digital signatures with SHA-256, following the Alice -> Bob flow."""
import hmac
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.exceptions import InvalidSignature

# ASN.1 DigestInfo prefix for SHA-256 (RFC 8017, PKCS#1 v1.5).
# What actually gets encrypted is: prefix || hash, so the verifier knows
# which hash algorithm was used.
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
PADDING = padding.PKCS1v15()


def generate_key_pair(bits: int = 2048) -> tuple[bytes, bytes]:
    """Setup: Alice generates her RSA key pair. Returns (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sha256(message: str) -> bytes:
    """Hash the message with SHA-256 -> fixed 32-byte digest."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode("utf-8"))
    return digest.finalize()


def sign(message: str, private_key_pem: bytes) -> bytes:
    """
    Signing (Alice)
      2. Hash the message with SHA-256.
      3. "Encrypt" the hash with the private key -> signature.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    digest = sha256(message)                                            # step 2
    return private_key.sign(digest, PADDING, utils.Prehashed(hashes.SHA256()))  # step 3


@dataclass
class VerifyResult:
    valid: bool
    reason: str
    signed_hash: str | None = None
    computed_hash: str | None = None


def verify(message: str, signature: bytes, public_key_pem: bytes) -> VerifyResult:
    """
    Verification (Bob)
      6. "Decrypt" the signature with Alice's public key -> recover the signed hash.
      7. Hash the received message independently.
      8. Compare the two hashes.
    """
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Step 6: recover the DigestInfo that Alice signed (algorithm=None -> raw DigestInfo).
    try:
        recovered = public_key.recover_data_from_signature(signature, PADDING, None)
    except (InvalidSignature, ValueError):
        return VerifyResult(False, "Signature could not be decrypted with this public key "
                                   "(not signed by this key, or corrupted).")

    if (len(recovered) != len(SHA256_DIGEST_INFO_PREFIX) + 32
            or not recovered.startswith(SHA256_DIGEST_INFO_PREFIX)):
        return VerifyResult(False, "Decrypted signature is not a valid SHA-256 DigestInfo structure.")

    signed_hash = recovered[len(SHA256_DIGEST_INFO_PREFIX):]   # hash Alice signed
    computed_hash = sha256(message)                            # step 7: hash Bob computed

    valid = hmac.compare_digest(signed_hash, computed_hash)    # step 8: constant-time compare
    return VerifyResult(
        valid,
        "Hashes match: message is authentic and unmodified." if valid
        else "Hashes differ: message was tampered with, or the signature was not made by this key.",
        signed_hash.hex(),
        computed_hash.hex(),
    )
