# 🔐 Secure Transaction Encryption with AES-256-GCM & RSA Digital Signature

This project demonstrates how to securely encrypt sensitive customer transaction data using **AES-256 in GCM mode**, replacing insecure **AES-128-ECB**, and adds **digital signature verification** using **RSA** to ensure both confidentiality and authenticity.

---

## ✨ Features

- ✅ AES-256 encryption using **GCM mode** (ensures data confidentiality + integrity)
- 🔑 Strong **user-defined key** with validation
- 🛡️ **IV (Nonce)** handling for secure encryption
- 🔒 **Authentication Tag** generation and validation
- ✍️ **Digital Signature** using **RSA**:
  - Sign ciphertext with sender’s private key
  - Verify with sender’s public key
- 📊 **Performance comparison** with old AES-ECB
- 🚫 Rejected keys:
  - Weak keys like `shikhar`, `12414267`
  - Keys containing prime numbers: `2, 3, 5, 7, 11`

---

## 📦 Requirements

Install required libraries:

```bash
pip install pycryptodome
