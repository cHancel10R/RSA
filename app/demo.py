"""Runs the full Alice -> Bob flow locally, no server needed."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from app.signature import generate_key_pair, sha256, sign, verify

print("SETUP: Alice generates RSA key pair")
private_pem, public_pem = generate_key_pair()

print("\nSIGNING (Alice)")
message = "Pay Bob $100"
print("  message  :", message)
print("  SHA-256  :", sha256(message).hex())
signature = sign(message, private_pem)
print("  signature:", signature.hex()[:48] + "...")

print("\nVERIFICATION (Bob)")
print("  genuine  :", verify(message, signature, public_pem).valid)            # True
print("  tampered :", verify("Pay Bob $1000", signature, public_pem).valid)    # False
_, mallory_pub = generate_key_pair()
print("  wrong key:", verify(message, signature, mallory_pub).valid)           # False

# Sanity check: interoperable with the library's standard RSA-SHA256 verify.
pub = serialization.load_pem_public_key(public_pem)
pub.verify(signature, message.encode(), padding.PKCS1v15(), hashes.SHA256())
print("\nInterop with standard PKCS1v15/SHA-256 verify: True")
