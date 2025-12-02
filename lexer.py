def tokenize(cmd):
    cmd = cmd.lower().strip()
    tokens = []
    current = ""

    for ch in cmd:
        if ch.isspace():
            if current:
                tokens.append(current)
                current = ""
        else:
            current += ch # append character to current

    if current:
        tokens.append(current)

    return tokens


if __name__ == "__main__":
    print(tokenize("add github"))