import subprocess, hashlib, platform

def get_usb_serial_windows():
    out = subprocess.check_output([
        "powershell","-NoProfile","-Command",
        "Get-CimInstance Win32_DiskDrive | Select-Object SerialNumber"
    ]).decode(errors="ignore")
    serials = [s.strip() for s in out.splitlines() if s.strip() and "SerialNumber" not in s]
    return serials

if __name__ == "__main__":
    if platform.system() != "Windows":
        print("This helper is for Windows only.")
    else:
        serials = get_usb_serial_windows()
        if not serials:
            print("No USB serial found.")
        for s in serials:
            print("USB Serial:", s)
            print("SHA256 Hash:", hashlib.sha256(s.encode()).hexdigest())
            print("-"*60)
