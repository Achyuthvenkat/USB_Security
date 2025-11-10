import sqlite3

conn = sqlite3.connect('usb_security.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS authorized_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    usb_serial_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('encrypt','decrypt'))
)''')

c.execute('''CREATE TABLE IF NOT EXISTS encryption_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER,
    aes_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(device_id) REFERENCES authorized_devices(id)
)''')

conn.commit()
conn.close()
print("Database and tables created successfully!")