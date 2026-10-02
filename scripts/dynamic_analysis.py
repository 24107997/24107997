import sys
import os
import io
import zipfile
import re
import requests

THEZOO_NJRAT_URL = "https://github.com/ytisf/theZoo/raw/master/malware/Binaries/NJRat/NJRat.zip"

def download_from_thezoo(url=THEZOO_NJRAT_URL):
    """Tải mẫu njRAT từ repository theZoo và giải nén bằng mật khẩu 'infected'"""
    print(f"[+] Đang tải mẫu njRAT từ theZoo...")
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            print("[+] Tải thành công! Đang giải nén mẫu...")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                zf.extractall(path="/tmp/thezoo_njrat_dyn", pwd=b'infected')
                
            for root, dirs, files in os.walk("/tmp/thezoo_njrat_dyn"):
                for file in files:
                    return os.path.join(root, file)
    except Exception as e:
        print(f"[-] Lỗi tải từ theZoo: {e}")
    return None

def analyze_rat_dynamic():
    print(f"=== PHÂN TÍCH ĐỘNG / TRÍCH XUẤT CẤU HÌNH NJRAT TỪ THEZOO ===")
    target_file = download_from_thezoo()

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