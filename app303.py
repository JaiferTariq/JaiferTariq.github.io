import streamlit as st
from cryptography.fernet import Fernet

# ---------- Functions ----------
def generate_key(password: str) -> bytes:
    """Generate a Fernet key from a password"""
    # Fernet key must be 32 bytes base64-encoded
    import base64, hashlib
    hash = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hash)

def encrypt_message(msg: str, password: str) -> str:
    key = generate_key(password)
    cipher = Fernet(key)
    return cipher.encrypt(msg.encode()).decode()

def decrypt_message(encrypted_msg: str, password: str) -> str:
    try:
        key = generate_key(password)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_msg.encode()).decode()
    except Exception:
        return "❌ Unable to decrypt! Check the password or message."

# ---------- Streamlit UI ----------
st.set_page_config(page_title="Secure Secret Messenger", page_icon="🔒", layout="centered")
st.title("🔒 Secure Secret Messenger")
st.write("Send encrypted secret messages. Only friends with the correct password can decode them!")

mode = st.radio("Choose an action:", ["Encrypt a message", "Decrypt a message"])

if mode == "Encrypt a message":
    text = st.text_area("Enter your secret message:")
    password = st.text_input("Enter a secret password:", type="password")
    if st.button("Encrypt"):
        if text.strip() and password.strip():
            encrypted = encrypt_message(text, password)
            st.success("✅ Encrypted message:")
            st.code(encrypted)
            st.info("Share this message and the password only with your friend!")
        else:
            st.warning("Please enter both a message and a password!")

else:  # Decrypt
    encrypted_text = st.text_area("Paste the encrypted message:")
    password = st.text_input("Enter the password:", type="password")
    if st.button("Decrypt"):
        if encrypted_text.strip() and password.strip():
            decrypted = decrypt_message(encrypted_text, password)
            st.success("✅ Decrypted message:")
            st.code(decrypted)
        else:
            st.warning("Please enter both the encrypted message and password!")
