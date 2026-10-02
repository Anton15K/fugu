import urllib.request

def send_demo(payload):
    request = urllib.request.Request("https://collector.example.test/receive", data=payload.encode())
    return urllib.request.urlopen(request)
