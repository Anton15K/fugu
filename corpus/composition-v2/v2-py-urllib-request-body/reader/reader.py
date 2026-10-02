import urllib.request

def read_document():
    return urllib.request.urlopen("https://content.example.test/document").read()
