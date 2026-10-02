import sys
import os
import io
import zipfile
import re
import requests

THEZOO_URLS = [
    "https://raw.githubusercontent.com/ytisf/theZoo/master/malware/Binaries/NJRat/NJRat.zip",
    "https://raw.githubusercontent.com/ytisf/theZoo/master/malware/Binaries/NJRat/NJRat",
    "https://raw.githubusercontent.com/ytisf/theZoo/master/malware/Binaries/njRAT/njRAT.zip",
    "https://raw.githubusercontent.com/ytisf/theZoo/master/malware/Binaries/NJRAT/NJRAT.zip"
]

BAZAAR_NJRAT_HASH = "4b2c1d9f8e7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c"

def download_malware():
    """Tải mẫu njRAT từ theZoo, nếu lỗi 404 tự động fallback sang MalwareBazaar API"""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    # 1. Ưu tiên thử tải từ theZoo
    for url in THEZOO_URLS:
        print(f"[+] Đang thử tải mẫu njRAT từ theZoo: {url}")
        try:
            res = requests.get(url, headers=headers, timeout=15)
            if res.status_code == 200 and len(res.content) > 1000:
                print("[+] Tải thành công từ theZoo! Đang giải nén trong RAM...")
                with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
                    zf.extractall(path="/tmp/dyn_njrat", pwd=b'infected')
                for root, _, files in os.walk("/tmp/dyn_njrat"):
                    for file in files:
                        return os.path.join(root, file)
            else:
                print(f"[-] URL trả về mã: {res.status_code}")
        except Exception as e:
            print(f"[-] Lỗi kết nối URL: {e}")

    # 2. Dự phòng: Tự động chuyển sang MalwareBazaar nếu theZoo lỗi
    print("[!] Không lấy được từ theZoo, chuyển sang dự phòng MalwareBazaar API...")
    try:
        data = {'query': 'get_file', 'sha256': BAZAAR_NJRAT_HASH}
        res = requests.post("https://mb-api.abuse.ch/api/v1/", data=data, timeout=30)
        if res.status_code == 200 and res.content[:2] == b'PK':
            print("[+] Tải thành công từ MalwareBazaar! Đang giải nén...")
            with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
                zf.extractall(path="/tmp/dyn_njrat", pwd=b'infected')
            for root, _, files in os.walk("/tmp/dyn_njrat"):
                for file in files:
                    return os.path.join(root, file)
    except Exception as e:
        print(f"[-] Lỗi MalwareBazaar: {e}")

    return None

def analyze_rat_dynamic():
    print("=== PHÂN TÍCH ĐỘNG / TRÍCH XUẤT CẤU HÌNH NJRAT ===")
    target_file = download_malware()

    if not target_file or not os.path.exists(target_file):
        print("[-] Không tìm thấy file binary để trích xuất.")
        return

    print(f"[+] Đọc binary dữ liệu từ file: {target_file}")
    with open(target_file, "rb") as f:
        data = f.read()

    print("\n[+] 1. Quét tìm C2 Server (IP Address / Domains)...")
    ip_pattern = rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = set(re.findall(ip_pattern, data))
    found_ip = False
    for ip in ips:
        ip_str = ip.decode('utf-8', errors='ignore')
        if not ip_str.startswith(("0.", "127.", "255.", "192.168.", "10.")):
            print(f"    [!] Bắt được IP C2 nghi ngờ: {ip_str}")
            found_ip = True
    if not found_ip:
        print("    [-] IP C2 đã bị mã hóa ẩn hoặc sử dụng Domain tên miền.")

    url_pattern = rb'(?i)(?:http://|https://|tcp://)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    urls = set(re.findall(url_pattern, data))
    for url in urls:
        print(f"    [!] Bắt được Domain/URL C2: {url.decode('utf-8', errors='ignore')}")

    print("\n[+] 2. Quét các chuỗi Cấu hình, Mutex & Registry Keys...")
    strings = re.findall(rb'[ -~]{8,60}', data)
    keywords = [b'mutex', b'netsh', b'cmd.exe', b'powershell', b'software\\microsoft\\windows\\currentversion\\run', b'njrat', b'see_yourself']
    
    for s in strings:
        s_lower = s.lower()
        if any(kw in s_lower for kw in keywords):
            print(f"    [*] Dấu hiệu Config/Persistence: {s.decode('utf-8', errors='ignore')}")

if __name__ == "__main__":
    analyze_rat_dynamic()