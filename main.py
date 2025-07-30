import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QMessageBox
from PyQt5.QtGui import QIcon  # 
from auth import setup_admin, login_user, register_user, login_admin, is_locked
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QInputDialog, QMessageBox, QLineEdit

import os

class StartWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LexVault - Secure USB Vault")
        self.setGeometry(200, 200, 300, 300)
        self.setWindowIcon(QIcon("crypto.png"))
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.login_btn = QPushButton("🔓 Login with USB")
        self.register_btn = QPushButton("🆕 Register New USB User")
        self.setup_admin_btn = QPushButton("👑 Setup Admin")
        self.admin_login_btn = QPushButton("🛠 Admin Login")

        self.login_btn.clicked.connect(self.login)
        self.register_btn.clicked.connect(self.register)
        self.setup_admin_btn.clicked.connect(self.setup_admin)
        self.admin_login_btn.clicked.connect(self.admin_login)

        layout.addWidget(self.login_btn)
        layout.addWidget(self.register_btn)
        layout.addWidget(self.setup_admin_btn)
        layout.addWidget(self.admin_login_btn)

        self.setLayout(layout)

    def login(self):
        if is_locked():
            QMessageBox.warning(self, "Locked", "Vault is locked. Admin login required.")
        else:
            login_user(self)

    def register(self):
        register_user(self)

    def setup_admin(self):
        setup_admin(self)

    def admin_login(self):
        login_admin(self)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = StartWindow()
    window.show()
    sys.exit(app.exec_())
