import os
import json
import base64
from PyQt5.QtWidgets import QInputDialog, QMessageBox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from dashboard import Dashboard
from utils import get_usb_path, save_hidden_file, set_readonly, VAULT_LOCK_FILE
from PyQt5.QtWidgets import QInputDialog, QMessageBox, QLineEdit
# Replace echo=QLineEdit.Password

ATTEMPT_FILE = "failed_attempts.txt"
ADMIN_FILE = "admin_config.json"

def generate_keys(password):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_private, pem_public

def register_user(widget):
    usb = get_usb_path()
    if not usb:
        QMessageBox.warning(widget, "Error", "No USB drive found!")
        return

    username, ok = QInputDialog.getText(widget, "Username", "Enter new username:")
    if not ok or not username:
        return
    password, ok = QInputDialog.getText(widget, "Password", "Enter a strong password:", echo=QLineEdit.Password
)
    if not ok or not password:
        return

    priv_key, pub_key = generate_keys(password)
    save_hidden_file(os.path.join(usb, "private.pem"), priv_key)
    save_hidden_file(os.path.join(usb, "public.pem"), pub_key)
    with open(os.path.join(usb, "user_info.txt"), "w") as f:
        f.write(username)

    set_readonly(os.path.join(usb, "private.pem"))
    QMessageBox.information(widget, "Registered", "User registered successfully.")

def login_user(widget):
    usb = get_usb_path()
    if not usb:
        QMessageBox.warning(widget, "Error", "No USB drive found!")
        return

    password, ok = QInputDialog.getText(widget, "Password", "Enter your password:", echo=QLineEdit.Password
)
    if not ok or not password:
        return

    priv_path = os.path.join(usb, "private.pem")
    if not os.path.exists(priv_path):
        QMessageBox.warning(widget, "Error", "User not found on this USB.")
        return

    try:
        with open(priv_path, "rb") as f:
            serialization.load_pem_private_key(f.read(), password=password.encode())
        reset_attempts()
        widget.hide()
        dashboard = Dashboard()
        dashboard.exec_()
    except Exception:
        increment_attempts()
        QMessageBox.warning(widget, "Error", "Invalid password.")
        if get_attempts() >= 5:
            lock_vault()

def setup_admin(widget):
    if os.path.exists(ADMIN_FILE):
        QMessageBox.information(widget, "Already Set", "Admin already setup.")
        return

    password, ok = QInputDialog.getText(widget, "Set Admin Password", "Enter new admin password:", echo=QLineEdit.Password)
    if not ok or not password:
        return

    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    key = kdf.derive(password.encode())

    config = {
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(key).decode()
    }
    with open(ADMIN_FILE, "w") as f:
        json.dump(config, f)

    QMessageBox.information(widget, "Admin Setup", "Admin password set successfully.")

def login_admin(widget):
    if not os.path.exists(ADMIN_FILE):
        QMessageBox.warning(widget, "Error", "Admin not set.")
        return

    password, ok = QInputDialog.getText(widget, "Admin Login", "Enter admin password:", echo=QLineEdit.Password
)
    if not ok or not password:
        return

    with open(ADMIN_FILE) as f:
        config = json.load(f)

    salt = base64.b64decode(config["salt"])
    expected = base64.b64decode(config["hash"])

    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    try:
        kdf.verify(password.encode(), expected)
        reset_attempts()
        unlock_vault()
        widget.hide()
        dashboard = Dashboard()
        dashboard.exec_()
    except Exception:
        QMessageBox.warning(widget, "Error", "Invalid admin password.")

def lock_vault():
    with open(VAULT_LOCK_FILE, "w") as f:
        f.write("locked")

def unlock_vault():
    if os.path.exists(VAULT_LOCK_FILE):
        os.remove(VAULT_LOCK_FILE)

def is_locked():
    return os.path.exists(VAULT_LOCK_FILE)

def get_attempts():
    if not os.path.exists(ATTEMPT_FILE):
        return 0
    with open(ATTEMPT_FILE) as f:
        return int(f.read())

def increment_attempts():
    attempts = get_attempts() + 1
    with open(ATTEMPT_FILE, "w") as f:
        f.write(str(attempts))

def reset_attempts():
    if os.path.exists(ATTEMPT_FILE):
        os.remove(ATTEMPT_FILE)
