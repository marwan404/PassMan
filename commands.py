# 3d party imports
import pyperclip

# stdlib import
import getpass

# local imports
from prettyprint_helpers import *

# ================================
#        COMMAND FUNCTIONS
# ================================

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
