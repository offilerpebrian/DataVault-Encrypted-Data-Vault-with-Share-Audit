import os, json

class KV:
    def __init__(self, meta_path: str):
        self.meta_path = meta_path
        os.makedirs(os.path.dirname(meta_path), exist_ok=True)
        if not os.path.exists(meta_path):
            self._save({"version":1, "objects":{}})

    def _load(self):
        with open(self.meta_path,"r",encoding="utf-8") as f:
            return json.load(f)

    def _save(self, data):
        tmp = self.meta_path + ".tmp"
        with open(tmp,"w",encoding="utf-8") as f:
            json.dump(data,f,ensure_ascii=False,indent=2)
        os.replace(tmp, self.meta_path)

    def get(self):
        return self._load()

    def put_obj(self, name, meta):
        d = self._load()
        d["objects"][name] = meta
        self._save(d)

    def get_obj(self, name):
        return self._load()["objects"].get(name)

    def del_obj(self, name):
        d = self._load()
        d["objects"].pop(name, None)
        self._save(d)

    def list_objs(self):
        o = self._load()["objects"]
        return sorted(o.items())
