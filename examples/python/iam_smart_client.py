"""Reference client for the iAM Smart API (Python >= 3.9).

Requires: `pip install cryptography`. Uses only the standard library for HTTP.

Handles the CEK lifecycle, AES-256-GCM encryption, HMAC-SHA256 signing and callback
decryption as described in the iAM Smart API Specification v2.5.2 (sections 2.3-2.4).

    client = IamSmartClient(base_url, client_id, client_secret, private_key_pem)
    res = client.post("/api/v1/auth/getToken", {"code": code, "grantType": "authorization_code"})

The spec does not name the RSA padding used to wrap the CEK. rsa_padding="auto" (default)
tries PKCS#1 v1.5 first (Java's default for "RSA"), then OAEP-SHA1 and OAEP-SHA256.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import struct
import time
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SIGNATURE_METHOD = "HmacSHA256"
CEK_ERRORS = {"D30001", "D30002"}


class IamSmartError(Exception):
    def __init__(self, response: dict):
        super().__init__(f"{response.get('code')} {response.get('message')}")
        self.code = response.get("code")
        self.tx_id = response.get("txID")
        self.response = response


def encrypt_content(plaintext: bytes, cek: bytes) -> str:
    """AES/GCM/NoPadding with a 12-byte IV; Base64(int32 ivLength || iv || ciphertext || tag)."""
    iv = os.urandom(12)
    ct = AESGCM(cek).encrypt(iv, plaintext, None)  # ciphertext || 16-byte tag
    return base64.b64encode(struct.pack(">i", len(iv)) + iv + ct).decode()


def decrypt_bytes(content_b64: str | bytes, cek: bytes) -> bytes:
    data = base64.b64decode(content_b64)
    (iv_len,) = struct.unpack(">i", data[:4])
    if iv_len != 12:
        raise ValueError("invalid iv length")
    return AESGCM(cek).decrypt(data[4:16], data[16:], None)


def hkic_hash(hkic: str) -> str:
    """HKICHash: SHA-256 of the identifier without the check digit, Base64. Accepts 'A123456(7)'."""
    s = re.sub(r"\s+", "", hkic.upper())
    m = re.fullmatch(r"([A-Z]{1,2}\d{6})(?:\(([0-9A])\)|([0-9A]))?", s)
    if not m:
        raise ValueError("Expected an HKIC number such as A123456(7)")
    return base64.b64encode(hashlib.sha256(m.group(1).encode()).digest()).decode()


class IamSmartClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str, private_key_pem: str | bytes,
                 rsa_padding: str = "auto", cek_safety_margin_ms: int = 60_000, timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        pem = private_key_pem.encode() if isinstance(private_key_pem, str) else private_key_pem
        self.private_key = serialization.load_pem_private_key(pem, password=None)
        self.rsa_padding = rsa_padding
        self.margin = cek_safety_margin_ms
        self.timeout = timeout
        self._cek: bytes | None = None
        self._cek_expires_at = 0
        self._last_ts = 0

    # -- signing ------------------------------------------------------------
    def _timestamp(self) -> int:
        self._last_ts = max(int(time.time() * 1000), self._last_ts + 1)  # never goes backwards
        return self._last_ts

    def sign(self, timestamp: int, nonce: str, body: str) -> str:
        message = f"{self.client_id}{SIGNATURE_METHOD}{timestamp}{nonce}{body}"
        digest = hmac.new(self.client_secret.encode(), message.encode(), hashlib.sha256).digest()
        return urllib.parse.quote(base64.b64encode(digest).decode(), safe="")

    def headers(self, body: str, rate_limit_factor: dict | None = None) -> dict:
        ts = self._timestamp()
        nonce = uuid.uuid4().hex
        h = {
            "Content-Type": "application/json",
            "clientID": self.client_id,
            "signatureMethod": SIGNATURE_METHOD,
            "timestamp": str(ts),
            "nonce": nonce,
            "signature": self.sign(ts, nonce, body),
        }
        if rate_limit_factor:
            h["rateLimitFactor"] = base64.b64encode(json.dumps(rate_limit_factor, separators=(",", ":")).encode()).decode()
        return h

    # -- CEK ----------------------------------------------------------------
    def unwrap_key(self, secret_key_b64: str) -> bytes:
        wrapped = base64.b64decode(secret_key_b64)
        order = ["pkcs1", "oaep-sha1", "oaep-sha256"] if self.rsa_padding == "auto" else [self.rsa_padding]
        last = None
        for p in order:
            try:
                if p == "pkcs1":
                    key = self.private_key.decrypt(wrapped, rsa_padding.PKCS1v15())
                else:
                    h = hashes.SHA256() if p == "oaep-sha256" else hashes.SHA1()
                    key = self.private_key.decrypt(wrapped, rsa_padding.OAEP(mgf=rsa_padding.MGF1(h), algorithm=h, label=None))
                if len(key) != 32:
                    raise ValueError(f"unwrapped key is {len(key)} bytes")
                if self.rsa_padding == "auto":
                    self.rsa_padding = p
                return key
            except Exception as e:  # try the next padding
                last = e
        raise ValueError(f"Could not unwrap the CEK: {last}")

    def get_cek(self, force: bool = False) -> bytes:
        now = int(time.time() * 1000)
        if not force and self._cek and now < self._cek_expires_at - self.margin:
            return self._cek
        res = self._raw("/api/v1/security/getKey", "")
        if res.get("code") != "D00000":
            raise IamSmartError(res)
        c = res["content"]
        self._cek = self.unwrap_key(c["secretKey"])
        self._cek_expires_at = int(c["issueAt"]) + int(c["expiresIn"])
        return self._cek

    def revoke_cek(self) -> dict:
        res = self._raw("/api/v1/security/revokeKey", "")
        self._cek = None
        if res.get("code") != "D00000":
            raise IamSmartError(res)
        return res

    # -- requests -----------------------------------------------------------
    def _raw(self, path: str, body: str, rate_limit_factor: dict | None = None) -> dict:
        req = urllib.request.Request(self.base_url + path, data=body.encode() if body else b"",
                                     headers=self.headers(body, rate_limit_factor), method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode())

    def post(self, path: str, payload: dict, rate_limit_factor: dict | None = None, _retried: bool = False) -> dict:
        """Signed, encrypted POST. Returns the response with `content` decrypted."""
        cek = self.get_cek()
        body = json.dumps({"content": encrypt_content(json.dumps(payload, ensure_ascii=False).encode(), cek)})
        res = self._raw(path, body, rate_limit_factor)
        if res.get("code") in CEK_ERRORS and not _retried:
            self.get_cek(force=True)
            return self.post(path, payload, rate_limit_factor, True)
        if isinstance(res.get("content"), str) and res["content"]:
            res["content"] = json.loads(decrypt_bytes(res["content"], cek))
        return res

    # -- callbacks ----------------------------------------------------------
    def decrypt_callback(self, body: dict | str | bytes) -> dict:
        """Decrypts {txID, code, message, secretKey, content} sent to your callback endpoint."""
        data = json.loads(body) if isinstance(body, (str, bytes)) else dict(body)
        if not isinstance(data.get("content"), str) or not data["content"]:
            return data
        cek = self.unwrap_key(data.pop("secretKey"))
        data["content"] = json.loads(decrypt_bytes(data["content"], cek))
        return data
