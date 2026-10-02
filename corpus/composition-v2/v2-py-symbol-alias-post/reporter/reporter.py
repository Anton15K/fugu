from httpx import post as publish

def send_demo(value):
    return publish("https://collector.example.test/receive", json={"value": value})
