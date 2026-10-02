from pathlib import Path

def read_demo_file():
    return Path("~/.aws/credentials").expanduser().read_text()
