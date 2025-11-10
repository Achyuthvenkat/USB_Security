import os, hashlib, subprocess, socket, sqlite3, base64, struct, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

MAGIC = b'UEK1'
USB_PATH = "E:\\"  # your USB drive letter

def get_all_usb_serials():
    out = subprocess.check_output([
        "powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_DiskDrive | Where-Object {$_.InterfaceType -eq 'USB'} | Select-Object SerialNumber"
    ]).decode(errors="ignore")
    serials = [s.strip() for s in out.splitlines() if s.strip() and "SerialNumber" not in s and s.strip() != "------------"]
    return serials

def get_encrypt_device_id():
    hostname = socket.gethostname()
    conn = sqlite3.connect('usb_security.db')
    c = conn.cursor()
    serials = get_all_usb_serials()
    for serial in serials:
        usb_hash = hashlib.sha256(serial.encode()).hexdigest()
        c.execute("SELECT id FROM authorized_devices WHERE hostname=? AND usb_serial_hash=? AND role='encrypt'",
                  (hostname, usb_hash))
        row = c.fetchone()
        if row:
            conn.close()
            return row[0]
    conn.close()
    return None

def store_key_and_get_id(device_id, key_bytes):
    encoded_key = base64.b64encode(key_bytes).decode()
    conn = sqlite3.connect('usb_security.db')
    c = conn.cursor()
    c.execute("INSERT INTO encryption_keys (device_id, aes_key) VALUES (?, ?)", (device_id, encoded_key))
    conn.commit()
    key_id = c.lastrowid
    conn.close()
    return key_id

def encrypt_file(path, device_id):
    if not os.path.isfile(path) or path.endswith(".enc"):
        return
    try:
        with open(path, "rb") as f:
            data = f.read()
        key = AESGCM.generate_key(bit_length=256)
        key_id = store_key_and_get_id(device_id, key)
        aes = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, data, None)
        header = MAGIC + struct.pack(">Q", key_id) + nonce
        with open(path + ".enc", "wb") as f:
            f.write(header + ciphertext)
        os.remove(path)
        print(f"[+] Encrypted {os.path.basename(path)} (key_id={key_id})")
    except Exception as e:
        print(f"[!] Error encrypting {path}: {e}")

class EncryptWatcher(FileSystemEventHandler):
    def __init__(self, device_id):
        self.device_id = device_id
    def on_created(self, event):
        if not event.is_directory:
            time.sleep(1)
            encrypt_file(event.src_path, self.device_id)

if __name__ == "__main__":
    device_id = get_encrypt_device_id()
    if not device_id:
        print("[!] Device not authorized for encryption.")
    else:
        print(f"[+] Encrypting existing files in {USB_PATH}...")
        for root, _, files in os.walk(USB_PATH):
            for f in files:
                if not f.endswith(".enc"):
                    encrypt_file(os.path.join(root, f), device_id)

        print(f"[+] Watching {USB_PATH} for new files...")
        observer = Observer()
        observer.schedule(EncryptWatcher(device_id), USB_PATH, recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
