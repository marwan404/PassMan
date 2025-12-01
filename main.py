from argon2.low_level import hash_secret_raw, Type
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import getpass
import hmac
import hashlib
import json
import os
import secrets


def prRed(s): print("\033[91m {}\033[00m".format(s))
def prGreen(s): print("\033[92m {}\033[00m".format(s))
def prYellow(s): print("\033[93m {}\033[00m".format(s))


def initMode():

    master = getpass.getpass("ceate a master password: ")
    masterConfirm = getpass.getpass("confirm master password: ")

    while master != masterConfirm:
        prRed("ERROR! Incorrect confirmation")
        master = getpass.getpass("ceate a master password: ")
        masterConfirm = getpass.getpass("confirm master password: ")
        
    masterBytes = master.encode("utf-8") # convert master password from str to bytes
    salt = secrets.token_bytes(16)
    timeCost = 5 #how many reruns
    memoryCost = 131072 #128 MB which is how much memory the function uses
    parallelism = 4 #use 4 threads
    algType = Type.ID
    hashLen = 32 #AESGCM wants 32
    masterKey = hash_secret_raw(masterBytes, salt, timeCost, memoryCost, parallelism, hashLen, algType)
    # Derive encryption and auth subkeys from masterKey
    enc_key = hmac.new(masterKey, b"enc", hashlib.sha256).digest()
    auth_key = hmac.new(masterKey, b"auth", hashlib.sha256).digest()

    # Build verifier that proves password is correct without decrypting
    verifier = hmac.new(auth_key, b"verify", hashlib.sha256).digest()
    verifier_hex = binascii.hexlify(verifier).decode()
    
    vaultData = {}
    jsonVault = json.dumps(vaultData)
    jsonVault_bytes = jsonVault.encode("utf-8") # convert jsonVault to bytes
    
    nonce = secrets.token_bytes(12)

    e = AESGCM(enc_key)
    ciphertext = e.encrypt(nonce, jsonVault_bytes, None)

    salt_hex = binascii.hexlify(salt).decode()
    nonce_hex = binascii.hexlify(nonce).decode()
    ciphertext_hex = binascii.hexlify(ciphertext).decode()

    data = {
        'version': 1,
        'kdf': {
            'alg': 'argon2id',
            'salt': salt_hex,
            'time_cost': timeCost,
            'memory_cost': memoryCost,
            'parallelism': parallelism,
            'hash_len': hashLen
        },
        'auth': {
            'alg': 'hmac-sha256',
            'verifier': verifier_hex
        },
        'cipher': {
            'alg': 'aes-256-gcm',
            'nonce': nonce_hex
        },
        'vault': ciphertext_hex
    }
    with open(".vault", "w") as f: # create a .vault and pass all the data from the dict as json and then close the file
        json.dump(data, f, indent=4)
    
    prGreen("Vault created. Don't forget your password.")


def unlockMode():

    with open(".vault", "r") as f:
        data = json.load(f)

    salt = binascii.unhexlify(data["kdf"]["salt"])
    timeCost = data["kdf"]["time_cost"]
    memoryCost = data["kdf"]["memory_cost"]
    parallelism = data["kdf"]["parallelism"]
    hashLen = data["kdf"]["hash_len"]

    nonce = binascii.unhexlify(data["cipher"]["nonce"])

    verifier = binascii.unhexlify(data["auth"]["verifier"])

    ciphertext = binascii.unhexlify(data["vault"])

    master = getpass.getpass("enter your master password: ")
    master_bytes = master.encode("utf-8")

    masterKey = hash_secret_raw(master_bytes, salt, timeCost, memoryCost, parallelism, hashLen, Type.ID)

    auth_key = hmac.new(masterKey, b"auth", hashlib.sha256).digest()
    dec_key = hmac.new(masterKey, b"enc", hashlib.sha256).digest()
    verifierCalc = hmac.new(auth_key, b"verify", hashlib.sha256).digest()

    if hmac.compare_digest(verifierCalc, verifier):
        try:
            e = AESGCM(dec_key)
            plaintext = e.decrypt(nonce, ciphertext, None)
            prGreen("Vault unlocked")
        except Exception:
            prRed("UH OHHH!, we encounterd an issue")
            return
    else:
        prRed("Incorrect password BOZO!")
        return

    

def main():
    vaultPath = ".vault"

    if os.path.exists(vaultPath):
        unlockMode()
    else:
        initMode()

main()