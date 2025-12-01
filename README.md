# 🔐 Local CLI Password Manager

A secure, single-user, offline **Command-Line Password Manager** built in Python. This project focuses on **real cryptographic design**, not shortcuts. No cloud. No plaintext on disk. No stored passwords.

---

## ✅ Current Status

## ✅ Phase 1 – Cryptographic Lock System: COMPLETE

Implemented a production-grade security foundation including:

* Secure master password handling
* Strong key derivation using **Argon2id**
* Cryptographic key hierarchy (**auth key vs encryption key**)
* HMAC-based password verification
* Authenticated encryption using **AES-256-GCM**
* Fully encrypted on-disk vault

The vault can be securely created and unlocked using only the correct master password.

---

## 🔒 Security Design Overview

### 1. Master Password

* Entered using hidden input (`getpass`)
* Never stored on disk
* Used only temporarily in memory for key derivation

---

### 2. Key Derivation Function (KDF)

```text
Password + Salt → Argon2id → Master Key (32 bytes)
```

**Parameters:**

* Algorithm: `Argon2id`
* Salt: 16 bytes (random per vault)
* Time Cost: 5
* Memory Cost: 131072 KB (128 MB)
* Parallelism: 4
* Output Length: 32 bytes

This configuration provides strong resistance against offline brute‑force attacks.

---

### 3. Key Hierarchy (Separated Keys)

From the `master_key`, two independent subkeys are derived using HMAC:

```text
enc_key  = HMAC-SHA256(master_key, "enc")
auth_key = HMAC-SHA256(master_key, "auth")
```

* `enc_key` → Vault encryption & decryption
* `auth_key` → Password verification

This cleanly separates authentication from encryption.

---

### 4. Password Verification (Verifier System)

```text
verifier = HMAC-SHA256(auth_key, "verify")
```

* Stored in the vault file
* Recomputed on every unlock attempt
* Compared using constant-time comparison (`hmac.compare_digest`)

This allows the system to:

* Reject wrong passwords without attempting decryption
* Detect corrupted vault files independently

---

### 5. Vault Encryption

* Algorithm: `AES-256-GCM`
* Nonce: 12 random bytes per encryption
* Key: `enc_key`
* Integrity: GCM authentication tag (built-in)

Only encrypted ciphertext is stored on disk.

---

### 6. Vault File Format

```json
{
  "version": 1,
  "kdf": { ... },
  "auth": { "verifier": "..." },
  "cipher": { "nonce": "..." },
  "vault": "..."
}
```

Includes:

* KDF parameters
* HMAC password verifier
* AES-GCM nonce
* AES-GCM ciphertext

---

### ✅ Security Guarantees

| Threat              | Protected    |
| ------------------- | ------------ |
| File Theft          | ✅            |
| Offline Brute Force | ✅ (Argon2id) |
| Vault Tampering     | ✅ (AES-GCM)  |
| Password Leakage    | ✅            |
| Timing Attacks      | ✅            |

---

## ▶️ How to Run

```bash
python main.py
```

Behavior:

* If `.vault` does not exist → prompts to create a master password
* If `.vault` exists → prompts to unlock with master password

---

## 🗂️ Planned Roadmap

### 🟡 Phase 2 — Vault Functionality

* Store password entries (site, username, password)
* Commands:

  * `add`
  * `get`
  * `list`
  * `exit` (re-encrypt & save)

All operations occur in RAM only. Vault is re‑encrypted on exit.

---

### 🟠 Phase 3 — Security Hardening

* Brute-force delay
* Attempt limits
* Clipboard safety
* Secure memory wiping

---

### 🔵 Phase 4 — Usability Improvements

* Password generator
* Entry editing
* Entry deletion
* Search & filtering
* Improved CLI layout

---

### 🟣 Phase 5 — Advanced Security (Optional)

* Per-entry encryption
* Key rotation
* Encrypted backups

---

## ⚠️ Disclaimer

This project is for **educational and personal use**. While it uses strong cryptographic primitives, it has not undergone a professional security audit.

---

## 🛠️ Tech Stack

* Python 3.x
* `argon2-cffi`
* `cryptography`

---

## 🏁 Author

Marwan Ahmed
