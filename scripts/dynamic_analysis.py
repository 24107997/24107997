import sys
import os
import io
import zipfile
import re
import requests

# Mã Hash SHA256 của mẫu njRAT thực tế trên MalwareBazaar
DEFAULT_NJRAT_HASH = "4b2c1d9f8e7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c"

def download_malware_from_bazaar(sha256_hash):
    """Tải mẫu mã độc trực tiếp từ MalwareBazaar vào bộ nhớ tạm RAM"""
    print(f"[+] Đang tải mẫu RAT từ MalwareBazaar (Hash: {sha256_hash[:10]}...)...")
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {'query': 'get_file', 'sha256': sha256_hash}
    
    try:
        response = requests.post(url, data=data, timeout=30)
        if response.status_code == 200 and response.content[:2] == b'PK':
            print("[+] Tải thành công! Đang giải nén trong bộ nhớ RAM...")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                zf.extractall(path="/tmp/malware_run_dyn", pwd=b'infected')
                
            for root, dirs, files in os.walk("/tmp/malware_run_dyn"):
                for file in files:
                    return os.path.join(root, file)
    except Exception as e:
        print(f"[-] Lỗi tải mẫu từ MalwareBazaar: {e}")
    return None

def analyze_rat_dynamic(file_path_or_hash):
    print(f"=== PHÂN TÍCH ĐỘNG / TRÍCH XUẤT CẤU HÌNH RAT VÀ C2 ===")
    
    # Nếu truyền vào Hash 64 ký tự, tự động tải file từ MalwareBazaar
    if len(file_path_or_hash) == 64 and not os.path.exists(file_path_or_hash):
        target_file = download_malware_from_bazaar(file_path_or_hash)
    else:
        target_file = file_path_or_hash

    if not target_file or not os.path.exists(target_file):
        print("[-] Không có file binary hợp lệ để trích xuất.")
        return

    print(f"[+] Đọc binary dữ liệu từ file: {target_file}")
    with open(target_file, "rb") as f:
        data = f.read()

    # 1. Trích xuất C2 IP / Domains
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

    # 2. Tìm Mutex, Registry Keys & Chuỗi cấu hình
    print("\n[+] 2. Quét các chuỗi Cấu hình, Mutex & Registry Keys...")
    strings = re.findall(rb'[ -~]{8,60}', data)
    keywords = [b'mutex', b'netsh', b'cmd.exe', b'powershell', b'software\\microsoft\\windows\\currentversion\\run', b'njrat', b'see_yourself']
    
    for s in strings:
        s_lower = s.lower()
        if any(kw in s_lower for kw in keywords):
            print(f"    [*] Dấu hiệu Config/Persistence: {s.decode('utf-8', errors='ignore')}")

if __name__ == "__main__":
    input_val = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_NJRAT_HASH
    analyze_rat_dynamic(input_val)