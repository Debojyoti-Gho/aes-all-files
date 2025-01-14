import numpy as np
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import qrcode
from io import BytesIO
from PIL import Image
import cv2


# Function to generate a deterministic image
def generate_deterministic_image(n1, n2):
    img = Image.new("RGB", (100, 100), (int(abs(n1 * 255) % 256), int(abs(n2 * 255) % 256), 128))
    return img


# Function to hash an image
def hash_image(img):
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return hashlib.sha256(buffered.getvalue()).digest()


# Encrypt AES key with a hash
def encrypt_aes_key(aes_key, hash_key):
    cipher = AES.new(hash_key[:len(aes_key)], AES.MODE_ECB)
    return cipher.encrypt(pad(aes_key, AES.block_size))


# Decrypt AES key
def decrypt_aes_key(enc_key, hash_key):
    cipher = AES.new(hash_key[:len(enc_key)], AES.MODE_ECB)
    return unpad(cipher.decrypt(enc_key), AES.block_size)


# Streamlit UI
st.title("File Encryption and Decryption with Deterministic Image and QR Code")
st.info("developed by Debojyoti Ghosh")
# Initialize session state for encryption and decryption results
if "encrypted_file" not in st.session_state:
    st.session_state["encrypted_file"] = None
if "qr_code" not in st.session_state:
    st.session_state["qr_code"] = None
if "decrypted_file" not in st.session_state:
    st.session_state["decrypted_file"] = None

# Mode selection
mode = st.radio("Mode", ["Encrypt", "Decrypt"])
if mode == "Encrypt":
    file = st.file_uploader("Upload a File to Encrypt")
    aes_type = st.selectbox("AES Type", [128, 192, 256])
    n1 = st.number_input("Real Number N1", value=0.0, format="%.5f")
    n2 = st.number_input("Real Number N2", value=0.0, format="%.5f")
    
    if st.button("Encrypt"):
        if file:
            # Read file data
            file_data = file.read()
            
            # Generate AES key
            aes_key = get_random_bytes(aes_type // 8)
            
            # Generate deterministic image and hash it
            img = generate_deterministic_image(n1, n2)
            hash_key = hash_image(img)
            
            # Encrypt the AES key using the hash
            enc_aes_key = encrypt_aes_key(aes_key, hash_key)
            
            # Generate QR code for the encrypted AES key
            qr = qrcode.make(enc_aes_key)
            qr_buffer = BytesIO()
            qr.save(qr_buffer, format="PNG")
            qr_buffer.seek(0)
            
            # Encrypt the file data using the AES key
            cipher = AES.new(aes_key, AES.MODE_ECB)
            encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
            
            # Save results to session state
            st.session_state["encrypted_file"] = encrypted_data
            st.session_state["qr_code"] = qr_buffer
            
            st.success("Encryption Successful!")
        else:
            st.error("Please upload a file to encrypt.")

    # Show download buttons if encryption is done
    if st.session_state["encrypted_file"] and st.session_state["qr_code"]:
        st.download_button(
            label="Download Encrypted File",
            data=st.session_state["encrypted_file"],
            file_name="encrypted_file.bin",
            mime="application/octet-stream",
        )
        st.download_button(
            label="Download QR Code",
            data=st.session_state["qr_code"],
            file_name="encrypted_aes_key_qr.png",
            mime="image/png",
        )

elif mode == "Decrypt":
    encrypted_file = st.file_uploader("Upload Encrypted File", type=["bin"])
    qr_code_file = st.file_uploader("Upload QR Code (PNG)", type=["png"])
    aes_type = st.selectbox("AES Type", [128, 192, 256])
    n1 = st.number_input("Real Number N1", value=0.0, format="%.5f")
    n2 = st.number_input("Real Number N2", value=0.0, format="%.5f")
    
    if st.button("Decrypt"):
        if encrypted_file and qr_code_file:
            # Load and decode the QR code
            qr_image = np.array(Image.open(qr_code_file).convert("RGB"))
            qr_image = cv2.cvtColor(qr_image, cv2.COLOR_RGB2BGR)
            qr_detector = cv2.QRCodeDetector()
            qr_data, _, _ = qr_detector.detectAndDecode(qr_image)
            
            if not qr_data:
                st.error("Invalid QR code.")
            else:
                enc_aes_key = qr_data.encode('latin1')  # Preserve raw binary data
                
                # Regenerate the deterministic image and hash it
                img = generate_deterministic_image(n1, n2)
                hash_key = hash_image(img)
                hash_key_segment = hash_key[:aes_type // 8]
                
                # Decrypt the AES key
                aes_key = decrypt_aes_key(enc_aes_key, hash_key_segment)
                
                # Read encrypted file data
                encrypted_data = encrypted_file.read()
                
                # Decrypt the file
                cipher = AES.new(aes_key, AES.MODE_ECB)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
                
                # Save decrypted file in session state
                st.session_state["decrypted_file"] = decrypted_data
                
                st.success("Decryption Successful!")
        else:
            st.error("Please upload the encrypted file and QR code.")

    # Show download button if decryption is done
    if st.session_state["decrypted_file"]:
        st.download_button(
            label="Download Decrypted File",
            data=st.session_state["decrypted_file"],
            file_name="decrypted_file",
            mime="application/octet-stream",
        )
