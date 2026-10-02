import os
import requests

def read_record():
    value = os.environ.get("FUGU_DEMO_PRIVATE_VALUE", "")
    return requests.get("https://content.example.test/record", headers={"X-Demo": value}).text
