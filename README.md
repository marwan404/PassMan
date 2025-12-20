# 🔐 Local CLI Password Manager

[![CI](https://github.com/marwan404/PassMan/actions/workflows/ci.yml/badge.svg)](https://github.com/marwan404/PassMan/actions/workflows/ci.yml) [![Codecov](https://codecov.io/gh/marwan404/PassMan/branch/main/graph/badge.svg)](https://codecov.io/gh/marwan404/PassMan) [![Python](https://img.shields.io/badge/python-3.11%20%7C%203.13-blue)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A secure, single-user, offline **Command-Line Password Manager** built in Python. This project focuses on **proper cryptographic design, secure key management, and low-level system security principles** — not shortcuts. No cloud. No plaintext on disk. Zero trust in storage.

---

## ✅ Project Status

* ✅ **Phase 1** — Cryptographic Lock & Authentication System — **COMPLETE**
* ✅ **Phase 2** — Persistent Encrypted Vault + CLI Interpreter — **COMPLETE**
* 🟣 **Phase 3** — UX, Refactoring & Power-User Features — **IN PROGRESS**
* Planned: **Phase 4** — Advanced Security & Hardening

### Recent changes (2025-12-20)

* Added comprehensive unit tests (lexer, parser, crypto utilities, non-interactive command handlers) — **10 tests passing locally**.
* Added GitHub Actions CI (matrix on Python 3.11 & 3.13) that runs `pre-commit`, `black --check`, `ruff`, and `pytest`.
* Configured `pre-commit` with hooks for **Black** and **Ruff** and added `.pre-commit-config.yaml` and a `.gitignore` update.
* Standardized and added Google-style docstrings across `commands.py` and `crypto.py` and renamed several functions to snake_case for consistency.
* Reformatted the codebase with Black and fixed lint issues with Ruff.
* Added coverage reporting to CI and a Codecov badge to the README.
* Added a CodeQL security scanning workflow to run periodic security analysis.

---

## ✅ Phase 1 — Cryptographic Lock System (Complete)

A production-grade security foundation was implemented from scratch, including:

* Secure master password entry via `getpass`
* Strong memory-hard key derivation using **Argon2id**
* Cryptographic key hierarchy (**authentication key vs encryption key**)
* HMAC-based password verification
* Authenticated encryption using **AES-256-GCM**
* Fully encrypted on-disk vault with zero plaintext persistence

The vault can only be created and unlocked using the correct master password.

---

## ✅ Phase 2 — Encrypted Persistent Vault + CLI Interpreter (Complete)

Phase 2 transformed the cryptographic core into a fully usable encrypted password manager:

* Persistent encrypted storage with **automatic re-encryption on exit**
* Fresh AES-GCM nonce generated on every save
* Custom-built **command language**, including:

  * Lexer
  * Parser
  * AST nodes
  * Interpreter
* All decrypted secrets exist **only in RAM during execution**

### ✅ Supported Commands

| Command        | Description                            |
| -------------- | -------------------------------------- |
| `add <site>`   | Add or overwrite a password entry      |
| `get <site>`   | Retrieve username & password           |
| `edit <site>`  | Modify an existing entry               |
| `del <site>`   | Permanently delete an entry            |
| `search <str>` | Partial-match search on stored sites   |
| `ls`           | List all stored sites                  |
| `help`         | Show command usage                     |
| `exit`         | Securely re-encrypt and save the vault |

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

From the `master_key`, one independent subkey is derived using HMAC:

```text
enc_key  = HMAC-SHA256(master_key, "enc")
```

* `enc_key` -> Vault encryption & decryption.

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

| Threat | Protected |
| --- | --- |
| File Theft | ✅ |
| Offline Brute Force | ✅ |
| Vault Tampering | ✅ |
| Password Leakage | ✅ |
| Timing Attacks | ✅ |

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

## 🗂️ Development Roadmap

### ✅ Phase 1 — Cryptographic Core

* Secure unlock & vault creation

### ✅ Phase 2 — Persistent Encrypted Storage + CLI

* Full CRUD operations
* Encrypted save-on-exit system
* Custom lexer/parser command interpreter

### ⏳ Phase 3 — UX, Refactoring & Power Features (Current)

* Output formatting cleanup
* Internal code refactor & modularization
* Command help system
* Clipboard integration
* Entry editing
* Search functionality

### 🟣 Phase 4 — Advanced Security & Hardening (Planned)

* Per-entry encryption in memory
* Key rotation
* Secure encrypted backups
* Clipboard auto-clear timer
* Vault rebuild & integrity hardening
* Memory zeroization on exit

---

## ⚠️ Disclaimer

This project is for **educational and personal use**. While it uses strong cryptographic primitives and correct security design patterns, it has **not** undergone a professional security audit.

---

## Development

This project uses pre-commit to run formatting and linting tools on each commit.

* Black (code formatter)
* Ruff (linter/auto-fixer)

To install and enable the git hooks locally:

```bash
python -m pip install --user pre-commit
python -m pre_commit install
python -m pre_commit run --all-files
```

You can also run the tools directly:

```bash
python -m black .
python -m ruff check . --fix
```

---

## 🛠️ Tech Stack

* Python 3.13
* `argon2-cffi`
* `cryptography`
* `pyperclip`

---

## 🏁 Author

Marwan Ahmed
