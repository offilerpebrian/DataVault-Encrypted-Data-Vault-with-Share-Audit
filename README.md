# 🔐 DataVault — Encrypted Data Vault with Share & Audit

**DataVault** adalah proyek CLI untuk menyimpan file secara **terenkripsi end‑to‑end** dengan fitur **secure sharing** dan **audit trail**.  
Teknologi kunci: **AES‑256‑GCM**, **Argon2id (KDF)**, **X25519 (public‑key sharing)**, dan **HMAC chain** untuk memastikan log tidak dimanipulasi.

---

## ✨ Fitur
- **Enkripsi kuat (AES‑256‑GCM)** per file (file key/FK unik).
- **Password‑derived key** menggunakan **Argon2id** (salt + parameter kuat).
- **Secure sharing**: berbagi file key (FK) ke penerima via **X25519 sealed box**.
- **Audit trail** dengan **HMAC chaining** (tamper‑evident).
- **Key rotation** untuk mengganti password master.
- **Secure delete (best‑effort)** untuk menghapus konten terenkripsi.

---

## 🗂 Struktur
```
datavault/
├─ vault/
│  ├─ crypto.py
│  ├─ kvstore.py
│  ├─ audit.py
│  └─ utils.py
├─ cli.py
├─ requirements.txt
└─ README.md
```

---

## 🛠 Persyaratan
- Python 3.9+
- Dependencies:
  ```bash
  pip install -r requirements.txt
  ```

---

## ▶️ Cara Pakai (Contoh)
```bash
# 1) Siapkan lingkungan
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt

# 2) Inisialisasi vault (buat master key & keypair X25519)
python cli.py init

# 3) Tambahkan file (terenkripsi)
python cli.py add path/to/secret.pdf secret_pdf

# 4) Ambil/dekripsi file ke lokasi tujuan
python cli.py get secret_pdf out.pdf

# 5) Audit log integritas
python cli.py audit

# 6) Share file key (FK) untuk 'secret_pdf' ke penerima (gunakan public key penerima dalam hex)
#    Di sisi pengirim:
python cli.py share secret_pdf <RECIPIENT_PUBLIC_KEY_HEX>

#    Di sisi penerima (yang sudah punya keypair, hasil 'init' di mesinnya sendiri):
python cli.py accept <SHARE_TOKEN_HEX> shared_secret

# 7) Hapus aman objek terenkripsi
python cli.py shred secret_pdf

# 8) Rotasi password master
python cli.py rotate
```

> Public/Private key X25519 penerima dapat dilihat di `.vault/key.json` (field `pk`/`sk`). **Jangan membagikan `sk`**.  
> File terenkripsi disimpan sebagai `.vault/<name>.blob`. Metadata ada di `.vault/meta.json`. Log audit di `.vault/audit.log`.

---

## ⚠ Catatan Keamanan
- **Secure delete** bersifat best‑effort; pada filesystem/SSD modern tidak selalu menjamin data benar‑benar hilang.
- Pastikan melakukan **backup terproteksi** terhadap `.vault/key.json`. Kehilangan file ini dapat membuat data tidak bisa dipulihkan.
- Parameter Argon2id default sudah cukup kuat untuk demo. Sesuaikan di `vault/crypto.py` untuk produksi.

---

## 📌 Roadmap (opsional)
- Envelope encryption metadata (wrap FK dengan MK).
- Mode streaming untuk file besar.
- JSON report + GitHub Action untuk audit periodik.
- Recovery **Shamir Secret Sharing** untuk master key.
