import sys
import os
import io
import zipfile
import requests
import pefile

# Các đường dẫn URL dự phòng từ theZoo
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
                    zf.extractall(path="/tmp/static_njrat", pwd=b'infected')
                for root, _, files in os.walk("/tmp/static_njrat"):
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
                zf.extractall(path="/tmp/static_njrat", pwd=b'infected')
            for root, _, files in os.walk("/tmp/static_njrat"):
                for file in files:
                    return os.path.join(root, file)
    except Exception as e:
        print(f"[-] Lỗi MalwareBazaar: {e}")

    return None

def analyze_rat_static():
    print("=== PHÂN TÍCH TĨNH NJRAT (AUTOMATED PIPELINE) ===")
    target_exe = download_malware()

    if not target_exe or not os.path.exists(target_exe):
        print("[-] Không lấy được file binary để phân tích!")
        return

    print(f"[+] Tiến hành phân tích cấu trúc PE: {target_exe}")
    try:
        pe = pefile.PE(target_exe)
    except Exception as e:
        print(f"[-] Lỗi parse PE file: {e}")
        return

    print(f"[+] ImpHash (Vân tay IAT): {pe.get_imphash()}")
    
    rat_apis = {
        'Kết nối C2 (Mạng)': ['WSAStartup', 'socket', 'connect', 'send', 'recv', 'InternetOpenA'],
        'Keylogger (Theo dõi phím)': ['GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookExA', 'SetWindowsHookExW'],
        'Chụp màn hình': ['GetDC', 'BitBlt', 'CreateCompatibleBitmap'],
        'Ẩn mình / Process Injection': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
        'Ghi Registry (Khởi động cùng Win)': ['RegCreateKeyExA', 'RegSetValueExA']
    }

    print("\n--- PHÁT HIỆN CÁC API NGUY HIỂM TRONG IAT (IMPORT TABLE) ---")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            if entry.imports:
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        for category, apis in rat_apis.items():
                            if func_name in apis:
                                print(f"[!] DẤU HIỆU RAT [{category}]: Gọi hàm {func_name} ({dll_name})")

if __name__ == "__main__":
    analyze_rat_static()