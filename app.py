from flask import Flask, render_template, request, redirect, url_for
import sqlite3, hashlib, math

app = Flask(__name__)

def get_db():
    return sqlite3.connect('usb_security.db')

@app.route('/')
def index():
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Fetch authorized devices with latest key info
    c.execute('''
        SELECT ad.id, ad.hostname, ad.usb_serial_hash, ad.role,
               ek.id AS key_id, ek.aes_key, ek.created_at
        FROM authorized_devices ad
        LEFT JOIN (
            SELECT * FROM encryption_keys
            WHERE id IN (SELECT MAX(id) FROM encryption_keys GROUP BY device_id)
        ) ek ON ek.device_id = ad.id
        ORDER BY ad.id ASC
    ''')
    devices = c.fetchall()

    # Pagination setup for encryption keys (Audit)
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    c.execute("SELECT COUNT(*) as count FROM encryption_keys")
    total_rows = c.fetchone()['count']
    total_pages = math.ceil(total_rows / per_page) if total_rows else 1

    c.execute('''
        SELECT ek.id AS key_id, ek.device_id, ad.hostname, ad.role, ek.aes_key, ek.created_at
        FROM encryption_keys ek
        JOIN authorized_devices ad ON ad.id = ek.device_id
        ORDER BY ek.id DESC
        LIMIT ? OFFSET ?
    ''', (per_page, offset))
    keys = c.fetchall()

    conn.close()
    return render_template(
        'index.html',
        devices=devices,
        keys=keys,
        page=page,
        total_pages=total_pages
    )

@app.route('/add', methods=['POST'])
def add_device():
    hostname = request.form['hostname'].strip()
    usb_serial = request.form['usb_serial'].strip()
    role = request.form['role']
    usb_serial_hash = hashlib.sha256(usb_serial.encode()).hexdigest()

    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT INTO authorized_devices (hostname, usb_serial_hash, role) VALUES (?, ?, ?)',
              (hostname, usb_serial_hash, role))
    conn.commit()
    conn.close()
    return redirect('/')

@app.route('/edit/<int:device_id>', methods=['GET', 'POST'])
def edit_device(device_id):
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    if request.method == 'POST':
        hostname = request.form['hostname'].strip()
        usb_serial = request.form['usb_serial'].strip()
        role = request.form['role']
        usb_serial_hash = hashlib.sha256(usb_serial.encode()).hexdigest()

        c.execute('UPDATE authorized_devices SET hostname=?, usb_serial_hash=?, role=? WHERE id=?',
                  (hostname, usb_serial_hash, role, device_id))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))

    c.execute('SELECT * FROM authorized_devices WHERE id=?', (device_id,))
    device = c.fetchone()
    conn.close()
    return render_template('edit.html', device=device)

@app.route('/delete/<int:device_id>')
def delete_device(device_id):
    conn = get_db()
    c = conn.cursor()
    # Optional: also delete related keys
    c.execute('DELETE FROM encryption_keys WHERE device_id=?', (device_id,))
    c.execute('DELETE FROM authorized_devices WHERE id=?', (device_id,))
    conn.commit()
    conn.close()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
