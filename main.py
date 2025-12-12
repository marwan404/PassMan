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
import pyperclip
import secrets


def prRed(s): print("\033[91m{}\033[00m".format(s))
def prGreen(s): print("\033[92m{}\033[00m".format(s))
def prYellow(s): print("\033[93m{}\033[00m".format(s))


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
    return vaultData, enc_key


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

            prRed("decryption failed")
            return None
    else:
        prRed("decryption failed")
        prRed("exiting program")
        return None


def appendSiteData(site, vaultData):

    username = input("\nenter your username: ")
    password = getpass.getpass("enter your password: ")

    try:
        vaultData["entries"].append({
            'site' : site,
            'username' : username,
            'password' : password
        })
        
        prGreen(f":) {site} added")
        print()
    except Exception:
        prRed(f":( {site} couldn't be added")


def overwriteSiteData(site, i, vaultData):

    username = input("\nenter your username: ")
    password = getpass.getpass("enter your password: ")
    
    try:
        vaultData["entries"][i] = {
            'site' : site,
            'username' : username,
            'password' : password
        }
        
        prGreen(f":) {site} data overwritten!")
        print()
    except Exception:
        prRed(f":( {site} data couldnt be overwritten!")


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


def executeEdit(site, vaultData):
    
    found = False
    if vaultData["entries"]:
        for idx, entry in enumerate(vaultData["entries"]):
            if site == entry["site"]:
                found = True
                i = idx
                break
        
        if found:
            overwriteSiteData(site, i, vaultData)


def executeDel(site, vaultData):

    found = False
    if vaultData["entries"]:
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

    else:
        prRed("no saved passwords")


def executeGet(site, vaultData):

    found = False
    for entry in vaultData["entries"]:
        if site ==  entry["site"]:
            found = True
            prGreen(f"{site} found!")
            print(f"username: {entry['username']}")
            password = entry["password"]
            try:
                pyperclip.copy(password)
                print("password copied to clipboard")
            except pyperclip.PyperclipException:
                prYellow("password couldnt be copied")
                print(f"password: {password}")


    if not found:
        prYellow(f"{site} not found, would you like to add it? (y/n)")
        choice = input().lower()
        if choice in ['y', 'yes']:
            executeAdd(site, vaultData)
        else:
            return


def executeSearch(query, vaultData):
    
    if vaultData["entries"]:
        ls = []
        for entry in vaultData["entries"]:
            if query in entry["site"]:
                ls.append(entry["site"])
        if ls:
            for i, item in enumerate(ls):
                print(f"{i+1}. {item}")
        else:
            prYellow("no results")
    else:
        prYellow("there is currently no saved passwords")


def executeLs(vaultData):

    if vaultData["entries"]:
        counter = 0
        print("\n+-------+---------+")
        print("| index | Website |")
        print("+-------+---------+")
        for entry in vaultData["entries"]:
            counter += 1
            print(f"|   {counter}   | {entry['site']}    |")
        print("+-------+---------+")
            
    else:
        prYellow("there is currently no saved passwords")


def executeHelp():
    print("""
    +----------+--------------+---------------------------------------------------------------------------------------------------------------+
    | Commands |   Examples   |   Explanation                                                                                                 |
    +----------+--------------+---------------------------------------------------------------------------------------------------------------+
    | add      | add github   | creates a new entry for github and allows to add password and username                                        |
    | edit     | edit github  | allows to overwrite data in an already existing github entry                                                  |
    | get      | get github   | outputs username previously saved then and copies the password to the clipboard. outputs password on fallback |
    | del      | del github   | deletes entry of github from the entries                                                                      |
    | search   | search git   | searches in entries for query                                                                                 |
    | ls       | ls           | lits all current entries                                                                                      |
    | exit     | exit         | saves all data, encrypts it and closes program                                                                |
    +----------+--------------+---------------------------------------------------------------------------------------------------------------+
    """)


def executeExit():
    return "EXIT"


def execute(tree, vaultData):
    match tree.type:
        case "add":
            executeAdd(tree.site, vaultData)
        case "edit":
            executeEdit(tree.site, vaultData)
        case "del":
            executeDel(tree.site, vaultData)
        case "get":
            executeGet(tree.site, vaultData)
        case "search":
            executeSearch(tree.query, vaultData)
        case "ls":
            executeLs(vaultData)
        case "help":
            executeHelp()
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
        try:
            vaultData, enc_key = unlockMode()
            if not vaultData:
                return
        except(TypeError):
            return
    else:
        try:
            vaultData, enc_key = initMode()
            if not vaultData:
                return
        except TypeError:
            return

    prYellow("enter commands to execute functions. enter 'help' if you find trouble with any functions")

    while not ext:
        
        try:

            command = input("> ")

            tokens = tokenize(command)
            tree = parse(tokens)
            
            while not tree:
                command = input("> ")

                tokens = tokenize(command)
                tree = parse(tokens)

            action = execute(tree, vaultData)    
            if action == "EXIT":
                save(vaultData, enc_key)
                ext = True

        except KeyboardInterrupt:

            prYellow("\nKeyboard interrupt detected")
            try:
                save(vaultData, enc_key)
            except Exception:
                prRed("Couldn't save data, exiting without save!")
                return
            prGreen("Vault changes saved")
            prGreen("Exiting with save!")
            return


if __name__ == "__main__":
    main()