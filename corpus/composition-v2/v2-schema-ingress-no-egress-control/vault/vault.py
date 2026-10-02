import os

def read_demo_value():
    return os.getenv("FUGU_DEMO_PRIVATE_VALUE", "")
