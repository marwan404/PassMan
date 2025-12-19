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

#local imports
from prettyprint_helpers import *

# ================================
#             DEBUG
# ================================

def json_safe(obj):
    if isinstance(obj, bytes):
        return to_hex(obj)
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [json_safe(v) for v in obj]
    return obj


def find_bytes(obj, path="root"):
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

def getMaster():
    master = getpass.getpass("ceate a master password: ")
    masterConfirm = getpass.getpass("confirm master password: ")

    return master, masterConfirm


def derriveKey(master_bytes, salt, timeCost, memoryCost, parallelism, hashLen):
    masterKey = hash_secret_raw(master_bytes, salt, timeCost, memoryCost, parallelism, hashLen, Type.ID)
    enc_key = hmac.new(masterKey, b"enc", hashlib.sha256).digest()

    return enc_key


def encryptVaultData(enc_key, nonce, jsonVault_bytes):
    e = AESGCM(enc_key)
    ciphertext = e.encrypt(nonce, jsonVault_bytes, None)

    return ciphertext


def to_hex(s):
    encoded = binascii.hexlify(s).decode()
    return encoded


def unHex(s):
    decoded = binascii.unhexlify(s)
    return decoded


def save(vaultData, enc_key):

    if not enc_key:
        data = json_safe(vaultData)
        with open(".vault", "w") as f:
            json.dump(data, f, indent=4)
        return

    # Ensure bytes are converted to safe JSON-friendly types before serializing
    jsonVault_bytes = json.dumps(json_safe(vaultData)).encode("utf-8")
    nonce = secrets.token_bytes(12)
    ciphertext_hex = to_hex(encryptVaultData(enc_key, nonce, jsonVault_bytes))

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

    master, confirm = getMaster()
    while master != confirm:
        prRed("ERROR! Incorrect confirmation")
        master, confirm = getMaster()
        
    master_bytes = master.encode("utf-8")
    salt = secrets.token_bytes(16)
    timeCost = 5
    memoryCost = 131072
    parallelism = 4 
    hashLen = 32
    enc_key = derriveKey(master_bytes, salt, timeCost, memoryCost, parallelism, hashLen)
    
    vaultData = {'entries': []}
    # Use json_safe so any future binary data is converted prior to serializing
    jsonVault_bytes = json.dumps(json_safe(vaultData)).encode("utf-8") # convert jsonVault to bytes
    
    nonce = secrets.token_bytes(12)
    ciphertext_hex = to_hex(encryptVaultData(enc_key, nonce, jsonVault_bytes))

    data = {
        'version': 1,
        'kdf': {
            'alg': 'argon2id',
            'salt': to_hex(salt),
            'time_cost': timeCost,
            'memory_cost': memoryCost,
            'parallelism': parallelism,
            'hash_len': hashLen
        },
        'cipher': {
            'alg': 'aes-256-gcm',
            'nonce': to_hex(nonce)
        },
        'vault': ciphertext_hex
    }

    with open(".vault", "w") as f:
        json.dump(json_safe(data), f, indent=4)
    
    prGreen("Vault created. Don't forget your password.")
    return vaultData, enc_key


def unlock():

    with open(".vault", "r") as f:
        data = json.load(f)

    salt = unHex(data["kdf"]["salt"])
    timeCost = data["kdf"]["time_cost"]
    memoryCost = data["kdf"]["memory_cost"]
    parallelism = data["kdf"]["parallelism"]
    hashLen = data["kdf"]["hash_len"]
    nonce = unHex(data["cipher"]["nonce"])
    ciphertext = unHex(data["vault"])
    master_bytes = getpass.getpass("enter your master password: ").encode("utf-8")
    enc_key = derriveKey(master_bytes, salt, timeCost, memoryCost, parallelism, hashLen)

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
