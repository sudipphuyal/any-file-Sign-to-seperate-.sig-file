import json
from flask import Flask, request, render_template, send_file
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os

app = Flask(__name__)
SIGNATURE_FOLDER = 'signatures'
UPLOAD_FOLDER = 'uploads'

# Create directories if they don't exist
os.makedirs(SIGNATURE_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# This will store a dictionary of users and their private keys (for demo purposes)
users = {
    "PersonA": rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()),
    "PersonB": rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
}

def get_public_key_pem(private_key):
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sign', methods=['POST'])
def sign_file():
    signer = request.form.get('signer')
    if 'file' not in request.files or not signer or signer not in users:
        return "Invalid file or signer", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # Get the private key of the signer
    private_key = users[signer]

    # Read file content
    with open(filepath, 'rb') as f:
        file_content = f.read()

    # Sign the file content
    signature = private_key.sign(
        file_content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Get the public key in PEM format (to include in signature metadata)
    public_key_pem = get_public_key_pem(private_key)

    # Prepare signature metadata (signer's identity and public key)
    signature_data = {
        "signer": signer,
        "signature": signature.hex(),  # Store signature in hex format
        "public_key": public_key_pem
    }

    # Save the signature and metadata to a file
    signature_path = os.path.join(SIGNATURE_FOLDER, file.filename + '.sig')
    with open(signature_path, 'w') as sig_file:
        json.dump(signature_data, sig_file)

    return send_file(signature_path, as_attachment=True)

@app.route('/verify', methods=['POST'])
def verify_file():
    if 'file' not in request.files or 'signature' not in request.files:
        return "File or signature part missing", 400

    file = request.files['file']
    signature_file = request.files['signature']

    if file.filename == '' or signature_file.filename == '':
        return "No selected file or signature", 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    signature_path = os.path.join(SIGNATURE_FOLDER, signature_file.filename)

    file.save(filepath)
    signature_file.save(signature_path)

    # Read file content
    with open(filepath, 'rb') as f:
        file_content = f.read()

    # Read the signature data
    with open(signature_path, 'r') as sig_file:
        signature_data = json.load(sig_file)

    # Extract signature, signer identity, and public key
    signer = signature_data["signer"]
    signature = bytes.fromhex(signature_data["signature"])
    public_key_pem = signature_data["public_key"]

    # Load the public key from PEM format
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )

    # Verify signature
    try:
        public_key.verify(
            signature,
            file_content,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return f"Signature is valid. Signed by {signer}."
    except Exception as e:
        return f"Signature verification failed: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
