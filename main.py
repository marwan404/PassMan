"""
Vault CLI Password Manager
--------------------------
Secure password vault using Argon2id + AES-256-GCM.
"""

# =======================
# Standard Library
# =======================
import binascii
import getpass
import hashlib
import hmac
import json
import os
import secrets
from typing import Any, Dict, List, Optional, Tuple

# =======================
# Third Party
# =======================
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyperclip

# =======================
# Local Imports
# =======================
from lexer import tokenize
from command_parser import parse


VAULT_PATH = ".vault"


# =======================
# Pretty Printing
# =======================
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def spacer(lines: int = 1) -> None:
    """Print blank lines without extra spaces."""
    print("\n" * lines, end="")


def ok(msg: str) -> None:
    spacer()
    print(f"{Colors.GREEN}[ OK ]{Colors.RESET} {msg}")


def warn(msg: str) -> None:
    spacer()
    print(f"{Colors.YELLOW}[WARN]{Colors.RESET} {msg}")


def err(msg: str) -> None:
    spacer()
    print(f"{Colors.RED}[ERR ]{Colors.RESET} {msg}")


def info(msg: str) -> None:
    spacer()
    print(f"{Colors.CYAN}[INFO]{Colors.RESET} {msg}")


def kv(key: str, value: str) -> None:
    """Indented key-value output for grouped info."""
    print(f"    {key:<9}: {value}")


def prompt_yn(msg: str, default_no: bool = True) -> bool:
    """Ask a yes/no question and return True for yes."""
    suffix = " [y/N]" if default_no else " [Y/n]"
    choice = input(f"{msg}{suffix}: ").strip().lower()
    if not choice:
        return not default_no
    return choice in ("y", "yes")


def print_banner() -> None:
    print(f"{Colors.BOLD}{Colors.CYAN}Vault CLI{Colors.RESET} — type {Colors.BOLD}help{Colors.RESET} for commands")


# =======================
# Crypto Helpers
# =======================
def derive_keys(
    master_password: bytes,
    salt: bytes,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    hash_len: int,
) -> Tuple[bytes, bytes]:
    """Derive encryption and authentication keys from master password."""
    master_key = hash_secret_raw(
        master_password,
        salt,
        time_cost,
        memory_cost,
        parallelism,
        hash_len,
        Type.ID,
    )
    enc_key = hmac.new(master_key, b"enc", hashlib.sha256).digest()
    auth_key = hmac.new(master_key, b"auth", hashlib.sha256).digest()
    return enc_key, auth_key


def encrypt_vault(enc_key: bytes, vault_data: Dict[str, Any]) -> Tuple[bytes, bytes]:
    """Encrypt vault_data and return (nonce, ciphertext)."""
    plaintext = json.dumps(vault_data).encode("utf-8")
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(enc_key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_vault(enc_key: bytes, nonce: bytes, ciphertext: bytes) -> Dict[str, Any]:
    """Decrypt and parse vault JSON."""
    cipher = AESGCM(enc_key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


# =======================
# Vault File IO
# =======================
def load_vault_file() -> Optional[Dict[str, Any]]:
    """Read .vault JSON from disk."""
    try:
        with open(VAULT_PATH, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        err("Vault file not found.")
        return None
    except json.JSONDecodeError:
        err("Vault file is corrupted (invalid JSON).")
        return None
    except Exception as exc:  # CLI-friendly
        err(f"Failed to read vault file: {exc}")
        return None


def write_vault_file(data: Dict[str, Any]) -> bool:
    """Write .vault JSON to disk."""
    try:
        with open(VAULT_PATH, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
        return True
    except Exception as exc:  # CLI-friendly
        err(f"Failed to write vault file: {exc}")
        return False


# =======================
# Vault Initialization / Unlock
# =======================
def init_mode() -> Tuple[Optional[Dict[str, Any]], Optional[bytes]]:
    """Create a new encrypted vault."""
    info("Creating a new vault...")

    while True:
        master = getpass.getpass("Create master password: ")
        confirm = getpass.getpass("Confirm master password: ")

        if master == confirm:
            break
        err("Passwords do not match. Try again.")

    # KDF parameters
    salt = secrets.token_bytes(16)
    time_cost = 5
    memory_cost = 131072
    parallelism = 4
    hash_len = 32

    enc_key, auth_key = derive_keys(
        master.encode("utf-8"),
        salt,
        time_cost,
        memory_cost,
        parallelism,
        hash_len,
    )

    verifier = hmac.new(auth_key, b"verify", hashlib.sha256).digest()

    vault_data: Dict[str, Any] = {"entries": []}
    nonce, ciphertext = encrypt_vault(enc_key, vault_data)

    data = {
        "version": 1,
        "kdf": {
            "alg": "argon2id",
            "salt": binascii.hexlify(salt).decode(),
            "time_cost": time_cost,
            "memory_cost": memory_cost,
            "parallelism": parallelism,
            "hash_len": hash_len,
        },
        "auth": {
            "alg": "hmac-sha256",
            "verifier": binascii.hexlify(verifier).decode(),
        },
        "cipher": {
            "alg": "aes-256-gcm",
            "nonce": binascii.hexlify(nonce).decode(),
        },
        "vault": binascii.hexlify(ciphertext).decode(),
    }

    if not write_vault_file(data):
        err("Could not create vault file.")
        return None, None

    ok("Vault created. Don't forget your master password.")
    return vault_data, enc_key


def unlock_mode() -> Tuple[Optional[Dict[str, Any]], Optional[bytes]]:
    """Unlock an existing vault."""
    data = load_vault_file()
    if not data:
        return None, None

    try:
        salt = binascii.unhexlify(data["kdf"]["salt"])
        nonce = binascii.unhexlify(data["cipher"]["nonce"])
        verifier = binascii.unhexlify(data["auth"]["verifier"])
        ciphertext = binascii.unhexlify(data["vault"])

        time_cost = int(data["kdf"]["time_cost"])
        memory_cost = int(data["kdf"]["memory_cost"])
        parallelism = int(data["kdf"]["parallelism"])
        hash_len = int(data["kdf"]["hash_len"])
    except Exception:
        err("Vault file structure is invalid or missing fields.")
        return None, None

    master = getpass.getpass("Enter master password: ").encode("utf-8")

    enc_key, auth_key = derive_keys(master, salt, time_cost, memory_cost, parallelism, hash_len)
    calc_verifier = hmac.new(auth_key, b"verify", hashlib.sha256).digest()

    if not hmac.compare_digest(calc_verifier, verifier):
        err("Invalid password.")
        return None, None

    try:
        vault_data = decrypt_vault(enc_key, nonce, ciphertext)
        ok("Vault unlocked.")
        return vault_data, enc_key
    except Exception:
        err("Decryption failed. Vault may be corrupted.")
        return None, None


# =======================
# Vault Operations (UX-first)
# =======================
def vault_is_empty(vault_data: Dict[str, Any]) -> bool:
    """True if no entries are stored."""
    return not vault_data.get("entries")


def find_entry_index(site: str, entries: List[Dict[str, str]]) -> Optional[int]:
    """Return index of entry matching site, else None."""
    for idx, entry in enumerate(entries):
        if entry.get("site") == site:
            return idx
    return None


def add_entry(site: str, vault_data: Dict[str, Any]) -> None:
    """Add a new entry, with overwrite confirmation if it exists."""
    site = site.strip()
    if not site:
        err("Usage: add <site>")
        return

    entries = vault_data["entries"]
    existing_idx = find_entry_index(site, entries)

    if existing_idx is not None:
        warn(f"'{site}' already exists.")
        if not prompt_yn("Overwrite existing entry?"):
            info("Add cancelled.")
            return

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    new_entry = {"site": site, "username": username, "password": password}

    try:
        if existing_idx is not None:
            entries[existing_idx] = new_entry
            ok(f"'{site}' overwritten.")
        else:
            entries.append(new_entry)
            ok(f"'{site}' added.")
    except Exception as exc:
        err(f"Could not save entry in memory: {exc}")


def edit_entry(site: str, vault_data: Dict[str, Any]) -> None:
    """Edit an existing entry (must exist)."""
    if vault_is_empty(vault_data):
        warn("There are no saved entries.")
        return

    site = site.strip()
    if not site:
        err("Usage: edit <site>")
        return

    entries = vault_data["entries"]
    idx = find_entry_index(site, entries)

    if idx is None:
        warn(f"'{site}' not found. Use 'add {site}' to create it.")
        return

    info(f"Editing '{site}' (leave blank to keep current username).")
    current_username = entries[idx].get("username", "")

    username = input(f"Username [{current_username}]: ").strip()
    if not username:
        username = current_username

    password = getpass.getpass("Password (new): ")

    try:
        entries[idx] = {"site": site, "username": username, "password": password}
        ok(f"'{site}' updated.")
    except Exception as exc:
        err(f"Could not update entry: {exc}")


def delete_entry(site: str, vault_data: Dict[str, Any]) -> None:
    """Delete a stored entry with confirmation."""
    if vault_is_empty(vault_data):
        warn("There are no saved entries.")
        return

    site = site.strip()
    if not site:
        err("Usage: del <site>")
        return

    entries = vault_data["entries"]
    idx = find_entry_index(site, entries)

    if idx is None:
        err(f"'{site}' not found.")
        return

    if not prompt_yn(f"Delete all data for '{site}'?"):
        info("Deletion cancelled.")
        return

    try:
        entries.pop(idx)
        ok(f"'{site}' deleted.")
    except Exception as exc:
        err(f"Could not delete entry: {exc}")


def get_entry(site: str, vault_data: Dict[str, Any]) -> None:
    """Print username and copy password to clipboard (fallback prints password)."""
    if vault_is_empty(vault_data):
        warn("There are no saved entries.")
        return

    site = site.strip()
    if not site:
        err("Usage: get <site>")
        return

    entries = vault_data["entries"]
    idx = find_entry_index(site, entries)

    if idx is None:
        warn(f"'{site}' not found.")
        if prompt_yn(f"Add '{site}' now?"):
            add_entry(site, vault_data)
        else:
            info("Get cancelled.")
        return

    entry = entries[idx]
    ok(site)
    kv("Username", entry.get("username", ""))

    password = entry.get("password", "")
    try:
        pyperclip.copy(password)
        kv("Password", "(copied to clipboard)")
    except pyperclip.PyperclipException:
        warn("Clipboard copy failed.")
        kv("Password", password)
    except Exception as exc:
        warn(f"Clipboard error: {exc}")
        kv("Password", password)


def search_entries(query: str, vault_data: Dict[str, Any]) -> None:
    """Search sites by substring match."""
    if vault_is_empty(vault_data):
        warn("There are no saved entries.")
        return

    query = query.strip()
    if not query:
        err("Usage: search <query>")
        return

    results = [e["site"] for e in vault_data["entries"] if query in e.get("site", "")]
    if not results:
        warn("No results.")
        return

    ok(f"Found {len(results)} result(s):")
    for i, site in enumerate(results, 1):
        print(f"  {i}. {site}")


def list_entries(vault_data: Dict[str, Any]) -> None:
    """List all stored site names."""
    if vault_is_empty(vault_data):
        warn("There are no saved entries.")
        return

    entries = vault_data["entries"]
    spacer()
    print("+-------+----------------------------+")
    print("| Index | Site                       |")
    print("+-------+----------------------------+")
    for i, entry in enumerate(entries, 1):
        site = entry.get("site", "")
        print(f"| {str(i).rjust(5)} | {site.ljust(26)[:26]} |")
    print("+-------+----------------------------+")


def print_help() -> None:
    spacer()

    rows = [
        ("add <site>", "Create a new entry"),
        ("edit <site>", "Edit an existing entry"),
        ("get <site>", "Show username + copy password"),
        ("del <site>", "Delete an entry (asks confirmation)"),
        ("search <query>", "Search sites by substring"),
        ("ls", "List all saved sites"),
        ("help", "Show this help table"),
        ("exit", "Save vault and quit"),
    ]

    cmd_width = max(len(r[0]) for r in rows + [("Command", "")]) + 2
    desc_width = max(len(r[1]) for r in rows + [("", "Description")]) + 2

    print("+" + "-" * cmd_width + "+" + "-" * desc_width + "+")
    print(f"| {'Command'.ljust(cmd_width-1)} | {'Description'.ljust(desc_width-1)}|")
    print("+" + "-" * cmd_width + "+" + "-" * desc_width + "+")
    for cmd, desc in rows:
        print(f"| {cmd.ljust(cmd_width-2)}| {desc.ljust(desc_width-2)}|")
    print("+" + "-" * cmd_width + "+" + "-" * desc_width + "+")
    spacer()


# =======================
# Persistence
# =======================
def save_vault(vault_data: Dict[str, Any], enc_key: bytes) -> bool:
    """Encrypt and save vault to disk (same format)."""
    data = load_vault_file()
    if not data:
        err("Cannot save because vault file couldn't be read.")
        return False

    try:
        nonce, ciphertext = encrypt_vault(enc_key, vault_data)
        data["cipher"]["nonce"] = binascii.hexlify(nonce).decode()
        data["vault"] = binascii.hexlify(ciphertext).decode()
    except Exception as exc:
        err(f"Encryption failed: {exc}")
        return False

    if write_vault_file(data):
        ok("Vault saved.")
        return True

    err("Vault NOT saved.")
    return False


# =======================
# Main Loop
# =======================
def main() -> None:
    """Program entry point."""
    print_banner()

    if os.path.exists(VAULT_PATH):
        vault_data, enc_key = unlock_mode()
    else:
        vault_data, enc_key = init_mode()

    if not vault_data or not enc_key:
        err("Exiting.")
        return

    while True:
        try:
            command = input("\n> ").strip()

            if not command:
                warn("Enter a command (try: help).")
                continue

            # Parse (avoid double errors: let parser speak if it already prints)
            try:
                tokens = tokenize(command)
                tree = parse(tokens)
            except Exception:
                # If your parser already prints "syntax error!", we don't spam a second line.
                # If it doesn't print, you can uncomment the line below.
                # err("Syntax error. Type 'help' for usage.")
                continue

            if not tree:
                warn("Invalid command. Type 'help'.")
                continue

            try:
                match tree.type:
                    case "add":
                        add_entry(tree.site, vault_data)
                    case "edit":
                        edit_entry(tree.site, vault_data)
                    case "del":
                        delete_entry(tree.site, vault_data)
                    case "get":
                        get_entry(tree.site, vault_data)
                    case "search":
                        search_entries(tree.query, vault_data)
                    case "ls":
                        list_entries(vault_data)
                    case "help":
                        print_help()
                    case "exit":
                        save_vault(vault_data, enc_key)
                        ok("Goodbye.")
                        return
                    case _:
                        warn("Unknown command. Type 'help'.")
            except Exception as exc:
                err(f"Command failed: {exc}")

        except KeyboardInterrupt:
            print()  # so ^C doesn't glue to the next line
            warn("Keyboard interrupt detected.")
            try:
                save_vault(vault_data, enc_key)
                ok("Exiting with save.")
            except Exception:
                err("Could not save. Exiting without saving.")
            return


if __name__ == "__main__":
    main()
