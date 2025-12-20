def prRed(s):
    print("\033[91m {}\033[00m".format(s))


# command nodes
class addCMD:
    def __init__(self, site):
        self.type = "add"
        self.site = site


class editCMD:
    def __init__(self, site):
        self.type = "edit"
        self.site = site


class delCMD:
    def __init__(self, site):
        self.type = "del"
        self.site = site


class getCMD:
    def __init__(self, site):
        self.type = "get"
        self.site = site


class lsCMD:
    def __init__(self):
        self.type = "ls"


class exitCMD:
    def __init__(self):
        self.type = "exit"


class helpCMD:
    def __init__(self):
        self.type = "help"


class searchCMD:
    def __init__(self, query):
        self.type = "search"
        self.query = query


def validatedTokens(tks):
    match tks[0]:
        case "add":
            if len(tks) != 2:
                prRed("syntax error! type 'help' for how to use")
                return False
            else:
                return True
        case "edit":
            if len(tks) != 2:
                prRed("syntax error! type 'help' for how to use")
                return False
            else:
                return True
        case "del":
            if len(tks) != 2:
                prRed("syntax error! type 'help' for how to use")
                return False
            else:
                return True
        case "get":
            if len(tks) != 2:
                prRed("syntax error! type 'help' for how to use")
                return False
            else:
                return True
        case "ls":
            if len(tks) != 1:
                prRed("syntax error! type 'help' for how to use")
                return False
            else:
                return True
        case "help":
            if len(tks) != 1:
                prRed("syntax error! type 'help' for how to use")
                return False
            else:
                return True
        case "search":
            if len(tks) != 2:
                prRed("syntax error! type 'help' for how to use")
                return False
            else:
                return True
        case "exit":
            if len(tks) != 1:
                prRed("syntax error! type 'help' for how to use")
                return False
            else:
                return True
        case _:
            prRed("invalid command, type 'help' for commands")
            return False


def parse(tks):
    if validatedTokens(tks):
        match tks[0]:
            case "add":
                return addCMD(tks[1].lower())
            case "edit":
                return editCMD(tks[1].lower())
            case "del":
                return delCMD(tks[1].lower())
            case "get":
                return getCMD(tks[1].lower())
            case "search":
                return searchCMD(tks[1].lower())
            case "ls":
                return lsCMD()
            case "help":
                return helpCMD()
            case _:
                return exitCMD()
    else:
        return None


if __name__ == "__main__":
    tree = parse(["search", "git"])
    print(tree.type, tree.query)

    tree = parse(["ls"])
    print(tree.type)
