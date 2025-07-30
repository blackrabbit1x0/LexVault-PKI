from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QFileDialog, QMessageBox, QInputDialog
from crypto_ops import sign_document, verify_document, encrypt_data, decrypt_data
import os
from PyQt5.QtWidgets import QInputDialog, QMessageBox, QLineEdit

class Dashboard(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LexVault Dashboard")
        self.setGeometry(200, 200, 400, 300)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("Welcome to LexVault!"))

        self.sign_btn = QPushButton("✍️ Sign Document")
        self.verify_btn = QPushButton("✅ Verify Document")
        self.encrypt_btn = QPushButton("🔐 Encrypt File")
        self.decrypt_btn = QPushButton("🔓 Decrypt File")

        self.sign_btn.clicked.connect(self.sign_file)
        self.verify_btn.clicked.connect(self.verify_file)
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        self.decrypt_btn.clicked.connect(self.decrypt_file)

        layout.addWidget(self.sign_btn)
        layout.addWidget(self.verify_btn)
        layout.addWidget(self.encrypt_btn)
        layout.addWidget(self.decrypt_btn)

        self.setLayout(layout)

    def sign_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Sign")
        if file_path:
            password, ok = QInputDialog.getText(self, "Password", "Enter private key password:", echo=QLineEdit.Password)
            if ok:
                try:
                    usb_path = self.get_usb_path()
                    with open(os.path.join(usb_path, "private.pem"), "rb") as f:
                        private_key = f.read()
                    with open(file_path, "rb") as f:
                        data = f.read()
                    signature = sign_document(private_key, data, password)
                    with open(file_path + ".sig", "wb") as f:
                        f.write(signature)
                    QMessageBox.information(self, "Success", "Document signed successfully!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))

    def verify_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Verify")
        sig_path, _ = QFileDialog.getOpenFileName(self, "Select Signature File")
        if file_path and sig_path:
            try:
                usb_path = self.get_usb_path()
                with open(os.path.join(usb_path, "public.pem"), "rb") as f:
                    public_key = f.read()
                with open(file_path, "rb") as f:
                    data = f.read()
                with open(sig_path, "rb") as f:
                    sig = f.read()
                result = verify_document(public_key, data, sig)
                if result:
                    QMessageBox.information(self, "Valid", "Signature is valid.")
                else:
                    QMessageBox.warning(self, "Invalid", "Signature is invalid.")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def encrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            password, ok = QInputDialog.getText(self, "Password", "Enter encryption password:", echo=QLineEdit.Password)
            if ok:
                try:
                    with open(file_path, "rb") as f:
                        data = f.read()
                    encrypted = encrypt_data(data, password)
                    with open(file_path + ".enc", "wb") as f:
                        f.write(encrypted)
                    QMessageBox.information(self, "Success", "File encrypted successfully!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))

    def decrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if file_path:
            password, ok = QInputDialog.getText(self, "Password", "Enter decryption password:", echo=QLineEdit.Password)
            if ok:
                try:
                    with open(file_path, "rb") as f:
                        encrypted_data = f.read()
                    decrypted = decrypt_data(encrypted_data, password)
                    save_path, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File As")
                    if save_path:
                        with open(save_path, "wb") as f:
                            f.write(decrypted)
                        QMessageBox.information(self, "Success", "File decrypted successfully!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", str(e))

    def get_usb_path(self):
        from utils import get_usb_path
        usb = get_usb_path()
        if not usb:
            raise Exception("USB drive not detected.")
        return usb
