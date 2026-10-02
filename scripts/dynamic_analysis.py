import sys
import re

def extract_rat_config(file_path):
    print(f"=== TRÍCH XUẤT CẤU HÌNH RAT ===")
    with open(file_path, "rb") as f:
        data = f.read()

    print("[+] Tìm kiếm C2 Server (IP/Domain)...")
    ips = set(re.findall(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', data))
    for ip in ips:
        ip_str = ip.decode('utf-8')
        if not ip_str.startswith(("0.", "127.", "255.")):
            print(f"[!] Phát hiện IP C2 nghi ngờ: {ip_str}")

    urls = set(re.findall(rb'(?i)(?:http://|https://|tcp://)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', data))
    for url in urls:
         print(f"[!] Phát hiện Domain C2 nghi ngờ: {url.decode('utf-8')}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "samples/sample_rat.exe"
    extract_rat_config(target)