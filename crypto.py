import os, hmac, hashlib, nacl.public
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

def argon2_kdf(password: bytes, salt: bytes, outlen=32, t=3, m=2**16, p=1):
    return hash_secret_raw(password, salt, time_cost=t, memory_cost=m, parallelism=p,
                           hash_len=outlen, type=Type.ID)

def mk_wrap(plaintext_mk: bytes, password: str, salt: bytes=None):
    if not salt: salt = os.urandom(16)
    kek = argon2_kdf(password.encode(), salt)
    nonce = os.urandom(12)
    ct = AESGCM(kek).encrypt(nonce, plaintext_mk, b"mk-wrap")
    return {"salt": salt.hex(), "nonce": nonce.hex(), "ct": ct.hex()}

def mk_unwrap(wrapped: dict, password: str):
    salt = bytes.fromhex(wrapped["salt"])
    nonce = bytes.fromhex(wrapped["nonce"])
    ct = bytes.fromhex(wrapped["ct"])
    kek = argon2_kdf(password.encode(), salt)
    return AESGCM(kek).decrypt(nonce, ct, b"mk-wrap")

def fk_encrypt(fk: bytes, plaintext: bytes, aad: bytes=b""):
    nonce = os.urandom(12)
    ct = AESGCM(fk).encrypt(nonce, plaintext, aad)
    return nonce, ct

def fk_decrypt(fk: bytes, nonce: bytes, ct: bytes, aad: bytes=b""):
    return AESGCM(fk).decrypt(nonce, ct, aad)

def new_key(n=32): return os.urandom(n)

def x25519_keypair():
    sk = nacl.public.PrivateKey.generate()
    return sk, sk.public_key

def x25519_seal(pubkey: nacl.public.PublicKey, data: bytes):
    box = nacl.public.SealedBox(pubkey)
    return box.encrypt(data)

def x25519_open(privkey: nacl.public.PrivateKey, sealed: bytes):
    box = nacl.public.SealedBox(privkey)
    return box.decrypt(sealed)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()
