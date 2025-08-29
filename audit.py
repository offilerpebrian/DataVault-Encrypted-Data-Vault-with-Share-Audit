import os, json, time
from .crypto import hmac_sha256

class AuditLog:
    def __init__(self, path: str, hmac_key: bytes):
        self.path = path
        self.hmac_key = hmac_key
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            open(path, "w", encoding="utf-8").write("")

    def _last_mac(self):
        last = b""
        if not os.path.exists(self.path): return last
        with open(self.path, "rb") as f:
            for line in f:
                try:
                    obj = json.loads(line.decode("utf-8"))
                    last = bytes.fromhex(obj["mac"])
                except: pass
        return last

    def append(self, evtype: str, detail: dict):
        ts = int(time.time())
        prev = self._last_mac()
        entry = {"ts": ts, "type": evtype, "detail": detail, "prev": prev.hex()}
        mac = hmac_sha256(self.hmac_key, json.dumps(entry, sort_keys=True).encode())
        entry["mac"] = mac.hex()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False)+"\n")

    def verify(self):
        prev = b""
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                obj = json.loads(line)
                mac = bytes.fromhex(obj["mac"])
                want = hmac_sha256(self.hmac_key, json.dumps(
                    {"ts": obj["ts"], "type": obj["type"], "detail": obj["detail"], "prev": obj["prev"]},
                    sort_keys=True).encode())
                if mac != want or obj["prev"] != prev.hex():
                    return False
                prev = mac
        return True
