import os, json, click, base64, nacl.public
from pathlib import Path
from vault.crypto import new_key, mk_wrap, mk_unwrap, fk_encrypt, fk_decrypt, x25519_keypair, x25519_seal, x25519_open
from vault.kvstore import KV
from vault.audit import AuditLog
from vault.utils import ensure_dir, secure_delete

VAULT_DIR = ".vault"
KEY_FILE = Path(VAULT_DIR)/"key.json"
META_FILE = Path(VAULT_DIR)/"meta.json"
AUDIT_FILE = Path(VAULT_DIR)/"audit.log"

def load_ctx(password: str):
    data = json.load(open(KEY_FILE,"r", encoding="utf-8"))
    mk = mk_unwrap(data["mk_wrap"], password)
    hmac_key = bytes.fromhex(data["audit_hmac"])
    return mk, AuditLog(str(AUDIT_FILE), hmac_key), KV(str(META_FILE))

@click.group()
def cli():
    pass

@cli.command()
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
def init(password):
    ensure_dir(VAULT_DIR)
    mk = new_key(32)
    mk_w = mk_wrap(mk, password)
    sk, pk = x25519_keypair()
    data = {"mk_wrap": mk_w, "pk": bytes(pk).hex(), "sk": bytes(sk).hex(), "audit_hmac": new_key(32).hex()}
    with open(KEY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    AuditLog(str(AUDIT_FILE), bytes.fromhex(data["audit_hmac"])).append("init", {})
    click.echo("✅ Vault initialized.")

@cli.command()
@click.argument("src", type=click.Path(exists=True))
@click.argument("name")
@click.option("--password", prompt=True, hide_input=True)
def add(src, name, password):
    mk, audit, kv = load_ctx(password)
    fk = new_key(32)
    aad = name.encode()
    with open(src, "rb") as f:
        nonce, ct = fk_encrypt(fk, f.read(), aad)
    out = Path(VAULT_DIR)/f"{name}.blob"
    with open(out, "wb") as f:
        f.write(nonce+ct)
    kv.put_obj(name, {"fk": base64.b64encode(fk).decode(), "aad": aad.decode(), "size": os.path.getsize(out)})
    audit.append("add", {"name":name, "size": os.path.getsize(out)})
    click.echo(f"✅ Added: {name}")

@cli.command()
@click.argument("name")
@click.argument("dst", type=click.Path())
@click.option("--password", prompt=True, hide_input=True)
def get(name, dst, password):
    mk, audit, kv = load_ctx(password)
    meta = kv.get_obj(name)
    if not meta:
        return click.echo("❌ Not found")
    blob_path = Path(VAULT_DIR)/f"{name}.blob"
    if not blob_path.exists():
        return click.echo("❌ Blob missing")
    blob = open(blob_path, "rb").read()
    nonce, ct = blob[:12], blob[12:]
    fk = base64.b64decode(meta["fk"].encode())
    data = fk_decrypt(fk, nonce, ct, meta["aad"].encode())
    with open(dst, "wb") as f:
        f.write(data)
    audit.append("get", {"name":name, "out":str(dst)})
    click.echo(f"✅ Decrypted to: {dst}")

@cli.command()
@click.argument("name")
@click.argument("recipient_pub_hex")
@click.option("--password", prompt=True, hide_input=True)
def share(name, recipient_pub_hex, password):
    mk, audit, kv = load_ctx(password)
    meta = kv.get_obj(name)
    if not meta:
        return click.echo("❌ Not found")
    fk = base64.b64decode(meta["fk"].encode())
    pub = nacl.public.PublicKey(bytes.fromhex(recipient_pub_hex))
    sealed = x25519_seal(pub, fk)
    token = sealed.hex()
    audit.append("share", {"name":name, "to":recipient_pub_hex[:16]})
    click.echo(f"🔑 Share token (FK sealed):\n{token}")

@cli.command()
@click.argument("share_token_hex")
@click.argument("name")
@click.option("--password", prompt=True, hide_input=True)
def accept(share_token_hex, name, password):
    mk, audit, kv = load_ctx(password)
    data = json.load(open(KEY_FILE,"r", encoding="utf-8"))
    sk = nacl.public.PrivateKey(bytes.fromhex(data["sk"]))
    fk = x25519_open(sk, bytes.fromhex(share_token_hex))
    kv.put_obj(name, {"fk": base64.b64encode(fk).decode(), "aad": name, "size": 0})
    audit.append("accept", {"name":name})
    click.echo("✅ Share accepted.")

@cli.command()
@click.argument("name")
@click.option("--password", prompt=True, hide_input=True)
def shred(name, password):
    mk, audit, kv = load_ctx(password)
    blob = Path(VAULT_DIR)/f"{name}.blob"
    if blob.exists():
        secure_delete(str(blob))
    kv.del_obj(name)
    audit.append("shred", {"name":name})
    click.echo("🗑️ Shredded.")

@cli.command("audit")
@click.option("--password", prompt=True, hide_input=True)
def audit_cmd(password):
    mk, audit, _ = load_ctx(password)
    ok = audit.verify()
    click.echo("✅ Audit log OK" if ok else "❌ Audit log TAMPERED")

@cli.command()
@click.option("--old", prompt="Old password", hide_input=True)
@click.option("--new", prompt="New password", hide_input=True, confirmation_prompt=True)
def rotate(old, new):
    data = json.load(open(KEY_FILE,"r", encoding="utf-8"))
    mk = mk_unwrap(data["mk_wrap"], old)
    data["mk_wrap"] = mk_wrap(mk, new)
    with open(KEY_FILE,"w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    click.echo("🔁 Master password rotated.")

if __name__ == "__main__":
    cli()
