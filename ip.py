#!/usr/bin/env python3
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from time import time
import os
from tqdm import tqdm
from ping3 import ping

TIMEOUT = 30
VERBOSE = True
DEBUG = False
PROXY = None  # contoh: 'http://1.1.1.1:80'

# =========================
# Cloudflare CIDR List
# =========================
CLOUDFLARE_CIDR = [
    "104.16.0.0/12",
    "172.64.0.0/13",
    "162.158.0.0/15",
    "198.41.128.0/17",
    "108.162.192.0/18",
    "141.101.64.0/18",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
]

# =========================
# Network class
# =========================
class Network:
    def __init__(self, a=1, b=1, c=1, d=1):
        self.a = int(a)
        self.b = int(b)
        self.c = int(c)
        self.d = int(d)
        self.start_a = int(a)
        self.start_b = int(b)
        self.start_c = int(c)
        self.start_d = int(d)
        self.end_a = 255
        self.end_b = 255
        self.end_c = 255
        self.end_d = 255

    def set_end(self, end_a, end_b, end_c, end_d):
        self.end_a = int(end_a)
        self.end_b = int(end_b)
        self.end_c = int(end_c)
        self.end_d = int(end_d)

    def set_subnet(self, subnet_mask):
        subnet_mask = int(subnet_mask)
        sub_a = ''
        sub_b = ''
        sub_c = ''
        sub_d = ''
        byte = 0
        while byte < 32:
            if 0 <= byte <= 7:
                sub_a += '0' if byte < subnet_mask else '1'
            elif 8 <= byte <= 15:
                sub_b += '0' if byte < subnet_mask else '1'
            elif 16 <= byte <= 23:
                sub_c += '0' if byte < subnet_mask else '1'
            elif 24 <= byte <= 31:
                sub_d += '0' if byte < subnet_mask else '1'
            byte += 1
        self.end_a = int(sub_a, 2) | self.start_a
        self.end_b = int(sub_b, 2) | self.start_b
        self.end_c = int(sub_c, 2) | self.start_c
        self.end_d = int(sub_d, 2) | self.start_d

    def __iter__(self):
        return self

    def __next__(self):
        self.d += 1
        if self.d > 255:
            self.d = 0
            self.c += 1
            if self.c > 255:
                self.c = 0
                self.b += 1
                if self.b > 255:
                    self.b = 0
                    self.a += 1
                    if self.a > 255:
                        raise StopIteration
        if (
            self.a == self.end_a
            and self.b == self.end_b
            and self.c == self.end_c
            and self.d == self.end_d
        ):
            raise StopIteration
        return f"{self.a}.{self.b}.{self.c}.{self.d}"

    def __len__(self):
        return (
            (self.end_a - self.start_a or 1)
            * (self.end_b - self.start_b or 1)
            * (self.end_c - self.start_c or 1)
            * (self.end_d - self.start_d or 1)
        )

    @property
    def start_ip(self):
        return f"{self.start_a}.{self.start_b}.{self.start_c}.{self.start_d}"

    @property
    def end_ip(self):
        return f"{self.end_a}.{self.end_b}.{self.end_c}.{self.end_d}"


# =========================
# Scan function
# =========================
def scan(ip_host):
    try:
        ping_val = ping(ip_host, size=8)
    except Exception:
        ping_val = None
    if ping_val is not None:
        try:
            with urllib.request.urlopen(f"http://{ip_host}", timeout=TIMEOUT) as response:
                status_code = response.getcode()
            return [ip_host, status_code]
        except urllib.error.HTTPError as e:
            return [ip_host, e]
        except Exception as e:
            return [ip_host, f"PING-Reply {e}"]
    return None


# =========================
# Banner
# =========================
def banner():
    print("     Welcome to IP Header scanner")
    print("_____________________________________")
    print("Scanner IP Headers Python")
    print("GitHub: https://github.com/clirimfurriku/SIPHpy")
    print("_____________________________________\n")


# =========================
# Manual Scan
# =========================
def manual_scan():
    print('IP Example: 192.168.1.1/24')
    ip_start = input('Please Enter start IP: ').split('.')
    if len(ip_start[-1].split('/')) == 2:
        subnet = ip_start[-1].split('/')[1]
        ip_start[-1] = ip_start[-1].split('/')[0]
        ip = Network(*ip_start)
        ip.set_subnet(subnet)
    else:
        ip_end = input('Please Enter last IP of the network: ').split('.')
        ip = Network(*ip_start)
        ip.set_end(*ip_end)
    run_scan(ip)


# =========================
# Auto: Single Cloudflare CIDR
# =========================
def auto_scan_single():
    print("Cloudflare CIDRs:")
    for idx, cidr in enumerate(CLOUDFLARE_CIDR, 1):
        print(f"[{idx}] {cidr}")
    choice = input("Choose CIDR (number): ").strip()
    try:
        cidr = CLOUDFLARE_CIDR[int(choice) - 1]
    except (IndexError, ValueError):
        print("Invalid choice.")
        return
    base_ip, subnet = cidr.split('/')
    ip = Network(*base_ip.split('.'))
    ip.set_subnet(int(subnet))
    run_scan(ip)


# =========================
# Auto: All Cloudflare CIDRs
# =========================
def auto_scan_all():
    for cidr in CLOUDFLARE_CIDR:
        print(f"\n=== Scanning {cidr} ===")
        base_ip, subnet = cidr.split('/')
        ip = Network(*base_ip.split('.'))
        ip.set_subnet(int(subnet))
        run_scan(ip)


# =========================
# Scan Runner
# =========================
def run_scan(ip):
    print(f'Total number of IPs on the network is {len(ip)}')
    responses = []
    start = time()

    with ThreadPoolExecutor(max_workers=(os.cpu_count() or 1) * 50) as executor:
        for i in tqdm(executor.map(scan, ip), total=len(ip), unit=' IP'):
            if i:
                responses.append(i)
                if VERBOSE:
                    print(i)

    took = time() - start
    print(f'It took {took:.2f}s to scan IPs from {ip.start_ip} to {ip.end_ip}')

    with open('results.txt', 'a') as file:
        for i in responses:
            file.write(str(i) + '\n')
    print(f'Results saved as results.txt at {os.getcwd()}')


# =========================
# Main Menu
# =========================
if __name__ == "__main__":
    banner()
    print("[1] Manual Scan (Custom IP/Subnet)")
    print("[2] Auto Scan (Choose One Cloudflare CIDR)")
    print("[3] Auto Scan (All Cloudflare CIDRs)")
    mode = input("Choose option: ").strip()

    if mode == "1":
        manual_scan()
    elif mode == "2":
        auto_scan_single()
    elif mode == "3":
        auto_scan_all()
    else:
        print("Invalid selection!")
