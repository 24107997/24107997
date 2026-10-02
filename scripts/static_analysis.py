import sys
import pefile

def analyze_rat_static(file_path):
    print(f"=== PHÂN TÍCH TĨNH RAT: {file_path} ===")
    pe = pefile.PE(file_path)
    
    rat_apis = ['WSAStartup', 'connect', 'send', 'recv', 'GetAsyncKeyState', 'SetWindowsHookExA', 'BitBlt', 'VirtualAllocEx']
    
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='ignore')
                    if func_name in rat_apis:
                        print(f"[!] Cảnh báo hành vi RAT: Phát hiện gọi hàm {func_name}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "samples/sample_rat.exe"
    analyze_rat_static(target)