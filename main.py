# stdlib imports
import os

# local imports
from lexer import tokenize
from parser import parse
from prettyprint_helpers import prRed, prGreen, prYellow
from crypto import init, unlock, find_bytes, save
from commands import execute

# ================================
#              MAIN
# ================================


def main():

    vaultPath = ".vault"
    ext = False

    if os.path.exists(vaultPath):
        try:
            vaultData, enc_key = unlock()
            if not vaultData:
                return
        except TypeError:
            return
    else:
        try:
            vaultData, enc_key = init()
            if not vaultData:
                return
        except TypeError:
            return

    prYellow(
        "enter commands to execute functions. enter 'help' if you find trouble with any functions"
    )

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
            except Exception as e:
                prRed("Couldn't save data, exiting without save!")
                prRed(
                    f"for reference here is the exception (add issue to github repo) {type(e).__name__}, Message: {e}"
                )
                find_bytes(vaultData, path=".vault")
                return
            prGreen("Vault changes saved")
            prGreen("Exiting with save!")
            return


if __name__ == "__main__":
    main()
