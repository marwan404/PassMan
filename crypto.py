# 3d party imports
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii

# stdlib imports
import getpass
import hmac
import hashlib
import json
import secrets
import time

# local imports
from prettyprint_helpers import prRed, prGreen

# ================================
#             DEBUG
# ================================


def json_safe(obj):
    """Recursively convert objects to JSON-serializable representations.

    - Converts bytes objects to their hex string representation using
      ``to_hex``.
    - Recursively walks dictionaries and lists and applies the same
      conversion to nested values.

    Args:
        obj: Any Python object that may contain bytes, dicts, or lists.

    Returns:
        A JSON-serializable representation of ``obj`` where bytes are
        converted to hex strings.
    """
    if isinstance(obj, bytes):
        return to_hex(obj)
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_safe(v) for v in obj]
    return obj


def find_bytes(obj, path="root"):
    """Recursively search ``obj`` and print locations of bytes values.

    This is a debug helper that prints the dotted path to any bytes objects
    contained within the given object. It is useful for locating unexpected
    binary data before serializing or debugging vault contents.

    Args:
        obj: The object to inspect (may be nested dicts/lists).
        path (str): The current traversal path (used internally).

    Returns:
        None
    """
    if isinstance(obj, bytes):
        print("BYTES FOUND AT:", path)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            find_bytes(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            find_bytes(v, f"{path}[{i}]")


# ================================
#        CRYPTO HELPERS
# ================================


def get_master():
    """Prompt the user to enter and confirm a master password.

    Prompts the user twice (creation and confirmation). The caller is expected
    to compare the returned values and re-prompt if they do not match.

    Returns:
        Tuple[str, str]: (master, masterConfirm)
    """
    master = getpass.getpass("create a master password: ")
    masterConfirm = getpass.getpass("confirm master password: ")

    return master, masterConfirm


def derive_key(master_bytes, salt, timeCost, memoryCost, parallelism, hashLen):
    """Derive an AES-GCM encryption key from the master password bytes.

    Uses Argon2id (via ``hash_secret_raw``) to derive a master key and then
    derives the final encryption key via HMAC-SHA256 with the literal
    label ``b"enc"``.

    Args:
        master_bytes (bytes): Master password bytes.
        salt (bytes): Salt used for Argon2.
        timeCost (int): Argon2 time cost parameter.
        memoryCost (int): Argon2 memory cost parameter in KB.
        parallelism (int): Argon2 parallelism parameter.
        hashLen (int): Length of the Argon2 output key in bytes.

    Returns:
        bytes: The derived encryption key.
    """
    masterKey = hash_secret_raw(
        master_bytes, salt, timeCost, memoryCost, parallelism, hashLen, Type.ID
    )
    enc_key = hmac.new(masterKey, b"enc", hashlib.sha256).digest()

    return enc_key


def encrypt_vault_data(enc_key, nonce, jsonVault_bytes):
    """Encrypt JSON bytes using AES-GCM with the provided key and nonce.

    Args:
        enc_key (bytes): AES-GCM key.
        nonce (bytes): 12-byte nonce for AES-GCM.
        jsonVault_bytes (bytes): The plaintext bytes to encrypt (JSON-encoded).

    Returns:
        bytes: The ciphertext including authentication tag.
    """
    e = AESGCM(enc_key)
    ciphertext = e.encrypt(nonce, jsonVault_bytes, None)

    return ciphertext


def to_hex(s):
    """Return a hex string representation of bytes.

    Args:
        s (bytes): Bytes to encode.

    Returns:
        str: Hexadecimal string.
    """
    encoded = binascii.hexlify(s).decode()
    return encoded


def from_hex(s):
    """Decode a hex string back to bytes.

    Args:
        s (str): Hexadecimal string.

    Returns:
        bytes: Decoded bytes.
    """
    decoded = binascii.unhexlify(s)
    return decoded


def save(vaultData, enc_key):
    """Persist the vault data to disk, either encrypted or plaintext.

    Behavior:
    - If ``enc_key`` is falsy, ``vaultData`` will be serialized (after
      applying ``json_safe``) directly to the file ".vault" as JSON.
    - If ``enc_key`` is provided, the function expects an existing ".vault"
      metadata file (with KDF and cipher metadata) and will replace the
      "cipher" nonce and "vault" ciphertext fields.

    Args:
        vaultData (dict): The vault data structure to save.
        enc_key (bytes|None): Encryption key, or falsy to save plaintext JSON.

    Returns:
        None

    Notes / TODOs:
        - If ".vault" does not exist when ``enc_key`` is provided, this
          function will raise an exception while attempting to read it. It may
          be desirable to create/initialize the metadata automatically or
          provide clearer error handling.
    """

    if not enc_key:
        data = json_safe(vaultData)
        with open(".vault", "w") as f:
            json.dump(data, f, indent=4)
        return

    # Ensure bytes are converted to safe JSON-friendly types before serializing
    jsonVault_bytes = json.dumps(json_safe(vaultData)).encode("utf-8")
    nonce = secrets.token_bytes(12)
    ciphertext_hex = to_hex(encrypt_vault_data(enc_key, nonce, jsonVault_bytes))

    # NOTE: This expects the .vault file to already exist with appropriate
    # metadata (kdf/cipher). If the file is missing or malformed, this will
    # raise. Consider handling FileNotFoundError and json.JSONDecodeError.
    with open(".vault", "r") as f:
        data = json.load(f)

    data["cipher"]["nonce"] = to_hex(nonce)
    data["vault"] = ciphertext_hex

    with open(".vault", "w") as f:
        json.dump(json_safe(data), f, indent=4)


# ================================
#          MAIN CRYPTO
# ================================


def init():
    """Initialize a new encrypted vault and write metadata to ".vault".

    - Prompts the user to set a master password (and confirm it via
      ``getMaster``).
    - Derives an encryption key using Argon2id with fixed parameters.
    - Creates an initial empty vault (``{'entries': []}``) and writes the
      encrypted vault together with KDF and cipher metadata to ".vault".

    Returns:
        tuple: (vaultData, enc_key)
            - vaultData (dict): The in-memory vault structure (initially empty).
            - enc_key (bytes): The derived encryption key for future operations.

    Notes / TODOs:
        - The Argon2 parameters (timeCost, memoryCost, parallelism, hashLen)
          are hard-coded. Consider making these configurable or adaptive to the
          runtime environment for better performance/compatibility.
    """

    master, confirm = get_master()
    while master != confirm:
        prRed("ERROR! Incorrect confirmation")
        master, confirm = get_master()

    master_bytes = master.encode("utf-8")
    salt = secrets.token_bytes(16)
    timeCost = 5
    memoryCost = 131072
    parallelism = 4
    hashLen = 32
    enc_key = derive_key(master_bytes, salt, timeCost, memoryCost, parallelism, hashLen)

    vaultData = {"entries": []}
    # Use json_safe so any future binary data is converted prior to serializing
    jsonVault_bytes = json.dumps(json_safe(vaultData)).encode(
        "utf-8"
    )  # convert jsonVault to bytes

    nonce = secrets.token_bytes(12)
    ciphertext_hex = to_hex(encrypt_vault_data(enc_key, nonce, jsonVault_bytes))

    data = {
        "version": 1,
        "kdf": {
            "alg": "argon2id",
            "salt": to_hex(salt),
            "time_cost": timeCost,
            "memory_cost": memoryCost,
            "parallelism": parallelism,
            "hash_len": hashLen,
        },
        "cipher": {"alg": "aes-256-gcm", "nonce": to_hex(nonce)},
        "vault": ciphertext_hex,
    }

    with open(".vault", "w") as f:
        json.dump(json_safe(data), f, indent=4)

    prGreen("Vault created. Don't forget your password.")
    return vaultData, enc_key


def unlock():
    """Open and decrypt the vault from disk by prompting for the master password.

    - Reads metadata and ciphertext from ".vault".
    - Derives the encryption key from the provided master password using the
      saved KDF parameters and attempts to decrypt with AES-GCM.

    Returns:
        tuple: (vaultData, enc_key) on success.
        None: If decryption fails or the decrypted JSON is invalid, prints error
            messages and returns None to indicate failure.

    Notes / TODOs:
        - The function prints error messages and returns None on failures. If a
          caller needs richer error handling, consider raising specific
          exceptions instead of printing and returning None.
    """

    with open(".vault", "r") as f:
        data = json.load(f)

    salt = from_hex(data["kdf"]["salt"])
    timeCost = data["kdf"]["time_cost"]
    memoryCost = data["kdf"]["memory_cost"]
    parallelism = data["kdf"]["parallelism"]
    hashLen = data["kdf"]["hash_len"]
    nonce = from_hex(data["cipher"]["nonce"])
    ciphertext = from_hex(data["vault"])
    master_bytes = getpass.getpass("enter your master password: ").encode("utf-8")
    enc_key = derive_key(master_bytes, salt, timeCost, memoryCost, parallelism, hashLen)

    try:
        e = AESGCM(enc_key)
        vault_bytes = e.decrypt(nonce, ciphertext, None)
        try:
            vaultData = json.loads(vault_bytes.decode("utf-8"))
        except Exception:
            prRed("Decryption succeeded but the vault JSON is invalid or corrupted!")
            time.sleep(2)
            prRed("Exiting program...")
            return
        return vaultData, enc_key
    except Exception:
        prRed("Decryption failed!")
        time.sleep(2)
        prRed("Exiting program...")
