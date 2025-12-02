# 🔐 Local CLI Password Manager

A secure, single-user, offline **Command-Line Password Manager** built in Python. This project focuses on **real cryptographic design and secure systems programming**, not shortcuts. No cloud. No plaintext on disk. Zero trust in storage.

---

## ✅ Current Status

* ✅ **Phase 1** — Cryptographic Lock & Authentication System: **COMPLETE**
* ✅ **Phase 2** — Persistent Encrypted Vault + Custom CLI Command System: **COMPLETE**
* ⏳ **Phase 3** — UX & Power-User Features (in progress)

---

## ✅ Phase 1 — Cryptographic Lock System (COMPLETE)

Implemented a production-grade security foundation including:

* Secure master password input via `getpass`
* Strong key derivation using **Argon2id**
* Cryptographic key hierarchy (**authentication key vs encryption key**)
* HMAC-based password verification
* Authenticated encryption using **AES-256-GCM**
* Fully encrypted on-disk vault with zero plaintext persistence

The vault can only be created and unlocked using the correct master password.

---

## ✅ Phase 2 — Encrypted Persistent Vault + CLI Interpreter (COMPLETE)

Phase 2 extended the cryptographic core into a fully usable encrypted password manager:

* Persistent storage with **automatic re-encryption on exit**
* Fresh AES-GCM nonce generated on every save
* Custom-built **command language** with:

  * Lexer
  * Parser
  * AST nodes
  * Interpreter
* All decrypted secrets live **only in RAM during execution**

### ✅ Supported Commands

| Command      | Description                            |
| ------------ | -------------------------------------- |
| `add <site>` | Add or overwrite a password entry      |
| `get <site>` | Retrieve username & password           |
| `del <site>` | Permanently delete an entry            |
| `ls`         | List all stored sites                  |
| `exit`       | Securely re-encrypt and save the vault |

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

This configuration provides strong resistance against offline brute-force attacks.

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
* Nonce: 12 random bytes (rotated on every save)
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
* If `.vault` exists → prompts to unlock with the master password
* All commands operate on decrypted data in RAM only

---

## 🗂️ Roadmap

### ✅ Phase 1 — Cryptographic Core

* Secure unlock & vault creation

### ✅ Phase 2 — Persistent Encrypted Storage + CLI

* Full CRUD operations
* Encrypted save-on-exit system

### ⏳ Phase 3 — UX & Power Features (In Progress)

* Search & filtering
* Clipboard auto-copy with timeout
* Password generator
* Entry editing
* Improved CLI output

### 🟣 Phase 4 — Advanced Security (Optional)

* Per-entry encryption
* Key rotation
* Secure encrypted backups
* Memory zeroization on exit

---

## ⚠️ Disclaimer

This project is for **educational and personal use**. While it uses strong cryptographic primitives and correct security design patterns, it has **not** undergone a professional security audit.

---

## 🛠️ Tech Stack

* Python 3.13
* `argon2-cffi`
* `cryptography`

---

## 🏁 Author

Marwan Ahmed
