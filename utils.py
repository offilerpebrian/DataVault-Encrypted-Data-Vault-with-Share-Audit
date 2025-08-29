import os, secrets

def secure_delete(path: str, passes: int=2):
    try:
        if not os.path.isfile(path):
            return
        size = os.path.getsize(path)
        with open(path,"r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(size))
        os.remove(path)
    except:
        pass

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)
