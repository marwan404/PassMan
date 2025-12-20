# 3d party imports
import pyperclip

# stdlib import
import getpass

# local imports
from prettyprint_helpers import prRed, prGreen, prYellow

# ================================
#        COMMAND FUNCTIONS
# ================================


def appendSiteData(site, vaultData):
    """Add a new entry for site to the vault.

    Prompts the user for a username and password and appends a dict with the
    keys 'site', 'username', and 'password' to vaultData['entries']. Prints a
    success message on success or an error message on failure.

    Args:
        site (str): The site name to add.
        vaultData (dict): Vault data containing an 'entries' list.

    Returns:
        None
    """

    username = input("\nenter your username: ")
    password = getpass.getpass("enter your password: ")

    try:
        vaultData["entries"].append(
            {"site": site, "username": username, "password": password}
        )

        prGreen(f":) {site} added")
        print()
    except Exception:
        prRed(f":( {site} couldn't be added")


def overwriteSiteData(site, i, vaultData):
    """Overwrite an existing entry at index i for the given site.

    Prompts the user for a username and password and replaces the entry at the
    given index in vaultData['entries'].

    Args:
        site (str): The site name.
        i (int): The index in vaultData['entries'] to overwrite.
        vaultData (dict): Vault data containing 'entries'.

    Returns:
        None
    """

    username = input("\nenter your username: ")
    password = getpass.getpass("enter your password: ")

    try:
        vaultData["entries"][i] = {
            "site": site,
            "username": username,
            "password": password,
        }

        prGreen(f":) {site} data overwritten!")
        print()
    except Exception:
        prRed(f":( {site} data couldnt be overwritten!")


def executeAdd(site, vaultData):
    """Add a new site entry or offer to overwrite if it already exists.

    Checks whether site is already present in vaultData['entries']. If present,
    asks the user whether to overwrite; otherwise appends a new entry by
    prompting for credentials.

    Args:
        site (str): Site name to add.
        vaultData (dict): Vault data containing 'entries'.

    Returns:
        None
    """

    found = False
    if vaultData["entries"]:
        for idx, entry in enumerate(vaultData["entries"]):
            if site == entry["site"]:
                found = True
                i = idx
                break

        if found:
            prYellow(
                "this site has already been added, would you like to overwrite it? (y/n)"
            )
            choice = input().lower()
            if choice in ["y", "yes"]:
                overwriteSiteData(site, i, vaultData)
            else:
                return
        else:
            appendSiteData(site, vaultData)
    else:
        appendSiteData(site, vaultData)


def executeEdit(site, vaultData):
    """Edit an existing site entry by overwriting it.

    Finds the entry matching site in vaultData['entries'] and calls
    overwriteSiteData to replace it. If the site is not found, no action is
    taken.

    Args:
        site (str): Site to edit.
        vaultData (dict): Vault data containing 'entries'.

    Returns:
        None
    """

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
    """Delete an entry matching site from vaultData['entries'].

    Prompts for confirmation before deleting. Prints an error message when no
    entries exist or when the site is not found.

    Args:
        site (str): Site to delete.
        vaultData (dict): Vault data containing 'entries'.

    Returns:
        None
    """

    found = False
    if vaultData["entries"]:
        for idx, entry in enumerate(vaultData["entries"]):
            if site == entry["site"]:
                found = True
                prYellow(
                    f"are you sure you want to delete all data associated with {site}? (y/n)"
                )
                choice = input().lower()
                if choice in ["y", "yes"]:
                    vaultData["entries"].pop(idx)
                    break
                else:
                    return

        if not found:
            prRed(f"{site} not found")

    else:
        prRed("no saved passwords")


def executeGet(site, vaultData):
    """Retrieve and display credentials for the given site.

    If the site is found, prints the saved username and attempts to copy the
    password to the system clipboard. On clipboard failure, prints the password
    instead. If the site is not found, prompts the user whether they want to
    add it.

    Args:
        site (str): Site to retrieve.
        vaultData (dict): Vault data containing 'entries'.

    Returns:
        None
    """

    found = False
    for entry in vaultData["entries"]:
        if site == entry["site"]:
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
        if choice in ["y", "yes"]:
            executeAdd(site, vaultData)
        else:
            return


def executeSearch(query, vaultData):
    """Search for entries whose site contains the given query and print matches.

    Prints an indexed list of matching site names or a message if there are no
    results.

    Args:
        query (str): Substring to search for in entry 'site' fields.
        vaultData (dict): Vault data containing 'entries'.

    Returns:
        None
    """

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
    """List saved sites in a simple indexed table format.

    Args:
        vaultData (dict): Vault data containing 'entries'.

    Returns:
        None
    """

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
    """Print the help table describing available commands and usage."""
    print(
        """
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
    """
    )


def executeExit():
    """Return the exit signal used by the main loop.

    Returns:
        str: The string "EXIT" used to signal program termination.
    """
    return "EXIT"


def execute(tree, vaultData):
    """Dispatch execution based on a parsed command tree.

    The tree object is expected to have a ``type`` attribute and other
    attributes depending on the command (for example, ``site`` or ``query``).
    This function calls the corresponding command handler. Unknown commands
    cause executeExit() to be returned.

    Args:
        tree: Parsed command tree with attributes such as type, site, or query.
        vaultData (dict): Vault data containing 'entries'.

    Returns:
        Any: Return value depends on dispatched handler (for example, "EXIT" when
            exit is requested).
    """
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
