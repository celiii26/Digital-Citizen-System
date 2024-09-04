from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import os
import qrcode
import datetime
import rsa  # Import rsa.py module
import cv2
import numpy as np
from pyzbar.pyzbar import decode
import base64
import hashlib

app = Flask(__name__)
app.secret_key = "secret"

def encode_base64(data):
    encoded_bytes = base64.b64encode(data.encode('utf-8'))
    encoded_str = encoded_bytes.decode('utf-8')
    return encoded_str

# Decode data from Base64
def decode_base64(encoded_str):
    decoded_bytes = base64.b64decode(encoded_str.encode('utf-8'))
    decoded_str = decoded_bytes.decode('utf-8')
    return decoded_str

# Fungsi untuk menghasilkan hash dari PIN
def hash_pin(pin):
    # Menggunakan SHA-256 untuk hashing
    hash_object = hashlib.sha256(pin.encode('utf-8'))
    return hash_object.hexdigest()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register_page')
def register_page():
    return render_template('register.html')

@app.route('/generate_qr_page')
def generate_qr_page():
    return render_template('generate_qr.html')

@app.route('/scan_qr_page')
def scan_qr_page():
    return render_template('scan_qr.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nik = request.form['nik']
        name = request.form['name']
        dob = request.form['dob']
        address = request.form['address']
        auth_code = request.form['auth_code']

        # Generate user's RSA keypair
        r = rsa.rsa()
        e, d, n = r.get_key(512)
        pubKey = (e, n)
        privKey = (d, n)

        auth_code = hash_pin(auth_code)

        # Save to database (keys are stored as strings for simplicity)
        with open('database.txt', 'a') as f:
            f.write(f"{nik}|{name}|{dob}|{address}|{auth_code}|{pubKey}|{privKey}\n")

        flash('Registration successful!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/generate_qr', methods=['POST'])
def generate_qr():
    nik = request.form['nik']
    auth_code = request.form['auth_code']
    auth_code = hash_pin(auth_code)
    print(auth_code)

    with open('database.txt', 'r') as f:
        for line in f:
            db_nik, _, _, _, db_auth_code, db_pubKey, db_privKey = line.strip().split('|')

            # Convert string representation back to tuple
            db_pubKey = eval(db_pubKey)
            db_privKey = eval(db_privKey)

            # Verify NIK and auth code
            if db_nik == nik and db_auth_code == auth_code:
                (d, n) = db_privKey
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                data = f'{nik},{timestamp}'

                # Hash and sign the data
                hashed_data = rsa.hashing(data)
                signature = rsa.rsa_sign(hashed_data, n, d)
                ds = rsa.signing(signature)

                qr_content = f'{timestamp}|{nik}|{db_pubKey}|{ds}'
                encoded_content = encode_base64(qr_content)

                # Generate QR code image
                qr = qrcode.make(encoded_content)
                qr_filename = f'{nik}_qrcode.png'
                qr_path = os.path.join('static', qr_filename)
                qr.save(qr_path)

                return send_file(qr_path, as_attachment=True, download_name=qr_filename)

    flash('Authorization failed!', 'danger')
    return redirect(url_for('home'))

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        if 'qr_image' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['qr_image']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        # Read image directly from the file without saving
        npimg = np.frombuffer(file.read(), np.uint8)
        image = cv2.imdecode(npimg, cv2.IMREAD_COLOR)

        # Decode the QR code from the image
        decoded_objects = decode(image)

        if not decoded_objects:
            flash('No QR code found in the image!', 'danger')
            return redirect(url_for('home'))

        qr_data_compressed = decoded_objects[0].data.decode('utf-8')
        qr_data = decode_base64(qr_data_compressed)

        try:
            time_str, nik, db_pubKey, ds = qr_data.split('|')

            qr_timestamp = datetime.datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S')
            current_time = datetime.datetime.now()

            # Check if the timestamp is within 60 seconds of the current time
            if (current_time - qr_timestamp).total_seconds() > 60:
                flash('Timestamp is out of range!', 'danger')
                return redirect(url_for('home'))
            
            # Convert string representation back to tuple
            db_pubKey = eval(db_pubKey)
            e, n = db_pubKey

            # Verify the digital signature
            hashed_data = rsa.hashing(f'{nik},{time_str}')
            if rsa.rsa_verify(ds, hashed_data, n, e):
                name = None
                with open('database.txt', 'r') as f:
                    for line in f:
                        db_nik, db_name, _, _, _, _, _ = line.strip().split('|')
                        if db_nik == nik:
                            name = db_name
                            break

                if name:
                    flash(f'QR code is valid! Pemilik Identitas: {name}', 'success')
                else:
                    flash('NIK tidak ditemukan di database!', 'danger')
            else:
                flash('Invalid QR code!', 'danger')
        except Exception as e:
            flash('Error processing QR code data!', 'danger')
            print(f'Error: {e}')

    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
