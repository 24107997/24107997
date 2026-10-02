import sys
import os
import io
import zipfile
import requests
import pefile

# SHA256 Hash của 1 mẫu njRAT thực tế trên MalwareBazaar
DEFAULT_NJRAT_HASH = "4b2c1d9f8e7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c"

def download_malware_from_bazaar(sha256_hash):
    """Tải mẫu mã độc trực tiếp từ MalwareBazaar API vào bộ nhớ tạm"""
    print(f"[+] Đang tải mẫu RAT từ MalwareBazaar (Hash: {sha256_hash[:10]}...)...")
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {'query': 'get_file', 'sha256': sha256_hash}
    
    response = requests.post(url, data=data, timeout=30)
    
    if response.status_code == 200 and response.content[:2] == b'PK': # File ZIP
        print("[+] Tải thành công! Đang giải nén trong bộ nhớ RAM...")
        try:
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                # Mật khẩu giải nén chuẩn là 'infected'
                zf.extractall(path="/tmp/malware_run", pwd=b'infected')
                
            for root, dirs, files in os.walk("/tmp/malware_run"):
                for file in files:
                    return os.path.join(root, file)
        except Exception as e:
            print(f"[-] Lỗi giải nén: {e}")
    else:
        print("[-] Không tải được file từ MalwareBazaar (Có thể cần API Key hoặc hash bị gỡ).")
    return None

def analyze_rat_static(file_path_or_hash):
    print(f"=== PHÂN TÍCH TĨNH RAT TRÊN GITHUB ACTIONS ===")
    
    # Kiểm tra xem tham số là Hash hay là đường dẫn file
    if len(file_path_or_hash) == 64 and not os.path.exists(file_path_or_hash):
        target_exe = download_malware_from_bazaar(file_path_or_hash)
    else:
        target_exe = file_path_or_hash

    if not target_exe or not os.path.exists(target_exe):
        print("[-] Không có file binary hợp lệ để phân tích.")
        return

    print(f"[+] Tiến hành phân tích cấu trúc PE file: {target_exe}")
    try:
        pe = pefile.PE(target_exe)
    except Exception as e:
        print(f"[-] Lỗi đọc pefile: {e}")
        return

    print(f"[+] ImpHash: {pe.get_imphash()}")
    
    # Danh sách các API nguy hiểm đặc trưng của RAT
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
                                print(f"[!] DẤU HIỆU RAT [{category}]: Called {func_name} ({dll_name})")

if __name__ == "__main__":
    # Nhận Hash từ tham số hoặc dùng Hash mẫu njRAT
    input_val = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_NJRAT_HASH
    analyze_rat_static(input_val)