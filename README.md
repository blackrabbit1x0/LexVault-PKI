# 🔐 LexVault-PKI

A secure USB-based authentication and document management system using public key infrastructure (PKI). Built with Python and PyQt5, LexVault replaces password-based login with encrypted RSA keys stored on USB drives and offers file signing, encryption, decryption, and signature verification in a fully offline environment.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

---

## 🧰 Features

- 🔑 **USB-Based Secure Login** (No password needed)
- 🖊️ **Digital Document Signing** (RSA-PSS + SHA-256)
- 🔐 **File Encryption/Decryption** (AES-GCM + RSA-OAEP)
- 📄 **Signature Verification** with X.509 certificates
- 🔒 **PIN Protection** with lockout after 5 attempts
- 🛡️ **Admin Override** with bcrypt-secured master password
- 🌐 **Offline Operation** (No internet needed)
- 💡 **User-Friendly GUI** built with PyQt5

---

## 🏗️ Project Structure

