import os, hashlib, subprocess, socket, sqlite3, base64, struct, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

MAGIC = b'UEK1'
USB_PATH = "E:\\"  # your USB drive
DEST_PATH = "D:\\Decrypted_Files"  # decrypted files folder

def get_all_usb_serials():
    out = subprocess.check_output([
        "powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_DiskDrive | Where-Object {$_.InterfaceType -eq 'USB'} | Select-Object SerialNumber"
    ]).decode(errors="ignore")
    serials = [s.strip() for s in out.splitlines() if s.strip() and "SerialNumber" not in s and s.strip() != "------------"]
    return serials

def authorized_decrypt():
    hostname = socket.gethostname()
    conn = sqlite3.connect('usb_security.db')
    c = conn.cursor()
    serials = get_all_usb_serials()
    for serial in serials:
        usb_hash = hashlib.sha256(serial.encode()).hexdigest()
        c.execute("SELECT 1 FROM authorized_devices WHERE hostname=? AND usb_serial_hash=? AND role='decrypt'",
                  (hostname, usb_hash))
        if c.fetchone():
            conn.close()
            return True
    conn.close()
    return False

def get_key_by_id(key_id):
    conn = sqlite3.connect('usb_security.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT aes_key FROM encryption_keys WHERE id=?", (key_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return base64.b64decode(row["aes_key"])

def decrypt_file(path):
    if not path.endswith(".enc"):
        return
    try:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) < 24 or data[:4] != MAGIC:
            return
        key_id = struct.unpack(">Q", data[4:12])[0]
        nonce = data[12:24]
        ciphertext = data[24:]
        key = get_key_by_id(key_id)
        if not key:
            print(f"[!] No key found for key_id={key_id}")
            return
        aes = AESGCM(key)
        plaintext = aes.decrypt(nonce, ciphertext, None)
        os.makedirs(DEST_PATH, exist_ok=True)
        out = os.path.join(DEST_PATH, os.path.basename(path).replace(".enc", ""))
        with open(out, "wb") as f:
            f.write(plaintext)
        print(f"[+] Decrypted {os.path.basename(path)} → {out}")
    except Exception as e:
        print(f"[!] Error decrypting {path}: {e}")

class DecryptWatcher(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".enc"):
            time.sleep(1)
            decrypt_file(event.src_path)

if __name__ == "__main__":
    if not authorized_decrypt():
        print("[!] Device not authorized for decryption.")
    else:
        print(f"[+] Decrypting existing encrypted files in {USB_PATH}...")
        for root, _, files in os.walk(USB_PATH):
            for f in files:
                if f.endswith(".enc"):
                    decrypt_file(os.path.join(root, f))

        print(f"[+] Watching {USB_PATH} for new encrypted files...")
        observer = Observer()
        observer.schedule(DecryptWatcher(), USB_PATH, recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
