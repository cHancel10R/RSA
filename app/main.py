import base64
import binascii
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import keystore
from .signature import sign, verify

app = FastAPI(title="RSA Digital Signature (SHA-256)")


class CreateKeysRequest(BaseModel):
    name: str


class SignRequest(BaseModel):
    signer: str
    message: str = Field(max_length=1_000_000)


class VerifyRequest(BaseModel):
    signer: str
    message: str = Field(max_length=1_000_000)
    signature: str  # base64


# ---- Setup (one time): Alice generates her key pair -------------------------
# Returns ONLY the public key. The private key stays on the server.
@app.post("/keys", status_code=201)
def create_keys(req: CreateKeysRequest):
    return {"name": req.name, "publicKey": keystore.create_keys(req.name)}


# Anyone (Bob) can fetch Alice's public key.
@app.get("/keys/{name}/public")
def get_public_key(name: str):
    return {"name": name, "publicKey": keystore.get_public_key(name).decode()}


# ---- Signing (Alice) ---------------------------------------------------------
# In production, protect this route with authentication: only Alice may sign as Alice.
@app.post("/sign")
def sign_message(req: SignRequest):
    signature = sign(req.message, keystore.get_private_key(req.signer))
    return {
        "signer": req.signer,
        "message": req.message,
        "signature": base64.b64encode(signature).decode(),
    }


# ---- Verification (Bob) ------------------------------------------------------
# Uses ONLY the public key. Always returns 200; check the "valid" field.
@app.post("/verify")
def verify_message(req: VerifyRequest):
    try:
        signature = base64.b64decode(req.signature, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, '"signature" must be valid base64.')
    result = verify(req.message, signature, keystore.get_public_key(req.signer))
    return {
        "valid": result.valid,
        "reason": result.reason,
        "signedHash": result.signed_hash,
        "computedHash": result.computed_hash,
    }


# ---- Frontend ------------------------------------------------------------
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(Path(__file__).resolve().parent.parent / "index.html")
