from argon2.low_level import hash_secret_raw, Type
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import getpass
import hmac
import hashlib
import json
from lexer import tokenize
import os
from parser import parse
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
    
    del master
    del master_bytes

    # Derive encryption and auth subkeys from masterKey
    enc_key = hmac.new(masterKey, b"enc", hashlib.sha256).digest()
    auth_key = hmac.new(masterKey, b"auth", hashlib.sha256).digest()
    del masterKey
    # Build verifier that proves password is correct without decrypting
    verifier = hmac.new(auth_key, b"verify", hashlib.sha256).digest()
    verifier_hex = binascii.hexlify(verifier).decode()
    
    vaultData = {'entries': []}
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
    enc_key = hmac.new(masterKey, b"enc", hashlib.sha256).digest()
    verifierCalc = hmac.new(auth_key, b"verify", hashlib.sha256).digest()

    if hmac.compare_digest(verifierCalc, verifier):
        try:

            e = AESGCM(enc_key)
            plaintext = e.decrypt(nonce, ciphertext, None)

            prGreen("Vault unlocked")

            plaintext_str = plaintext.decode("utf-8")
            vaultData = json.loads(plaintext_str)
            return vaultData, enc_key

        except Exception:
            prRed("UH OHHH!, we encounterd an issue")
            del masterKey
            del auth_key
            del enc_key
            del verifierCalc
            return None
    else:
        prRed("Incorrect password")
        prRed("exiting program")
        del masterKey
        del auth_key
        del enc_key
        del verifierCalc
        return None


def appendSiteData(site, vaultData):

    print(f"adding {site}...")
    username = input("enter your username: ")
    password = getpass.getpass("enter your password for this website: ")

    vaultData["entries"].append(
        {
            'site' : site,
            'username' : username,
            'password' : password
        }
    )


def overwriteSiteData(site, i, vaultData):
    print(f"overwriting {site}...")
    username = input("enter your username: ")
    password = getpass.getpass("enter your password for this website: ")
    vaultData["entries"][i] = {
        'site' : site,
        'username' : username,
        'password' : password
    }


def executeAdd(site, vaultData):

    found = False
    if vaultData["entries"]:
        for idx, entry in enumerate(vaultData["entries"]):
            if site == entry["site"]:
                found = True
                i = idx
                break

        if found:
            prYellow("this site has already been added, would you like to overwrite it? (y/n)")
            choice = input().lower()
            if choice in ['y', 'yes']:
                overwriteSiteData(site, i, vaultData)
            else:
                return
        else:
            appendSiteData(site, vaultData)
    else:
        appendSiteData(site, vaultData)


def executeDel(site, vaultData):

    found = False
    for idx, entry in enumerate(vaultData["entries"]):
        if site == entry["site"]:
            found = True
            prYellow(f"are you sure you want to delete all data associated with {site}? (y/n)")
            choice = input().lower()
            if choice in ['y', 'yes']:
                vaultData["entries"].pop(idx)
                break
            else:
                return
 
    if not found:
        prRed(f"{site} not found")


def executeGet(site, vaultData):

    found = False
    for entry in vaultData["entries"]:
        if site ==  entry["site"]:
            found = True
            prGreen(f"{site} found!")
            print(f"username: {entry['username']}")
            print(f"password = {entry['password']}")

    if not found:
        prYellow(f"{site} not found, would you like to add it? (y/n)")
        choice = input().lower()
        if choice in ['y', 'yes']:
            executeAdd(site, vaultData)
        else:
            return

def executeLs(vaultData):
    if vaultData["entries"]:
        counter = 0
        for entry in vaultData["entries"]:
            counter += 1
            print(f"{counter} {entry['site']}")
            
    else:
        prYellow("there is currently no saved passwords")

def executeExit():
    return "EXIT"


def execute(tree, vaultData):
    match tree.type:
        case "add":
            executeAdd(tree.site, vaultData)
        case "del":
            executeDel(tree.site, vaultData)
        case "get":
            executeGet(tree.site, vaultData)
        case "ls":
            executeLs(vaultData)
        case _:
            return executeExit()


def save(vaultData, enc_key):

    jsonVault_bytes = json.dumps(vaultData).encode("utf-8")
    nonce = secrets.token_bytes(12)

    e = AESGCM(enc_key)
    ciphertext = e.encrypt(nonce, jsonVault_bytes, None)

    nonce_hex = binascii.hexlify(nonce).decode()
    ciphertext_hex = binascii.hexlify(ciphertext).decode()

    with open(".vault", "r") as f:
        data = json.load(f)

    data["cipher"]["nonce"] = nonce_hex
    data["vault"] = ciphertext_hex

    with open(".vault", "w") as f:
        json.dump(data, f, indent=4)


def main():
    vaultPath = ".vault"
    ext = False

    if os.path.exists(vaultPath):
        vaultData, enc_key = unlockMode()
        if not vaultData:
            return
    else:
        initMode()
        vaultData, enc_key = unlockMode()
        if not vaultData:
            return

    prYellow("commands: add | get | del | ls | exit")

    while not ext:
        
        command = input("> ")

        tokens = tokenize(command)
        tree = parse(tokens)
        
        while not tree:
            prYellow("commands: add | get | del | ls | exit")
            command = input("> ")

            tokens = tokenize(command)
            tree = parse(tokens)

        action = execute(tree, vaultData)    
        if action == "EXIT":
            save(vaultData, enc_key)
            ext = True


main()