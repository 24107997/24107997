import sys
import os
import io
import zipfile
import requests
import pefile

THEZOO_NJRAT_URL = "https://github.com/ytisf/theZoo/raw/master/malware/Binaries/NJRat/NJRat.zip"

def download_from_thezoo(url=THEZOO_NJRAT_URL):
    """Tải mẫu njRAT từ repository theZoo và giải nén bằng mật khẩu 'infected'"""
    print(f"[+] Đang tải mẫu njRAT từ theZoo...")
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            print("[+] Tải thành công! Đang giải nén mẫu trong bộ nhớ tạm...")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                zf.extractall(path="/tmp/thezoo_njrat", pwd=b'infected')
                
            for root, dirs, files in os.walk("/tmp/thezoo_njrat"):
                for file in files:
                    if file.endswith('.exe') or file.endswith('.bin') or '.' not in file:
                        return os.path.join(root, file)
    except Exception as e:
        print(f"[-] Lỗi tải/giải nén từ theZoo: {e}")
    return None

def analyze_rat_static():
    print(f"=== PHÂN TÍCH TĨNH NJRAT TỪ THEZOO ===")
    target_exe = download_from_thezoo()

    if not target_exe or not os.path.exists(target_exe):
        print("[-] Không lấy được file executable từ theZoo.")
        return

    print(f"[+] Phân tích binary: {target_exe}")
    try:
        pe = pefile.PE(target_exe)
    except Exception as e:
        print(f"[-] Lỗi đọc pefile: {e}")
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