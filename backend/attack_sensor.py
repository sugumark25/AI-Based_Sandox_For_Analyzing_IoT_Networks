import requests
import random
import time

url = "http://127.0.0.1:5000/api/predict"

print("[ATTACK] Fake sensor attack started...")

while True:
    data = {
        "duration": 0.001,
        "src_pkts": random.randint(2000, 5000),
        "dst_pkts": random.randint(0, 5),
        "src_bytes": random.randint(500000, 2000000),
        "dst_bytes": random.randint(100, 500),
        "proto": "udp",
        "conn_state": "S0"
    }

    try:
        res = requests.post(url, json=data, timeout=2)
        print("[SENT]", data, "->", res.status_code, res.text)
    except Exception as e:
        print("[ERROR]", e)

    time.sleep(1)