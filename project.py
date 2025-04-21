import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# Constants
AES_KEY_SIZE = 32  # AES-256 key size
AES_IV_SIZE = 12   # Recommended IV size for GCM
AES_TAG_SIZE = 16
REJECTED_KEYS = {"shikhar", "12414267"}
PRIMES = {'2', '3', '5', '7', '11'}

# Validate user key
def validate_key(key_str):
    if key_str.lower() in REJECTED_KEYS:
        raise ValueError("Weak key! Choose a different key.")
    if any(p in key_str for p in PRIMES):
        raise ValueError("Key must not contain first five prime numbers.")
    return SHA256.new(key_str.encode()).digest()  # Hash to 32-byte key

# AES-GCM Encryption
def encrypt_AES_GCM(plaintext, key):
    iv = get_random_bytes(AES_IV_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return iv, ciphertext, tag

# AES-GCM Decryption
def decrypt_AES_GCM(iv, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

# Digital Signature
def generate_keys():
    key = RSA.generate(2048)
    return key, key.public_key()

def sign_data(data, private_key):
    digest = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(digest)

def verify_signature(data, signature, public_key):
    digest = SHA256.new(data)
    pkcs1_15.new(public_key).verify(digest, signature)

# Main Logic
if __name__ == "__main__":
    try:
        user_key = input("Enter a strong key: ")
        aes_key = validate_key(user_key)

        transaction_data = input("Enter transaction details: ").encode()

        # RSA Key Pair
        private_key, public_key = generate_keys()

        # Encrypt and time the operation
        start = time.time()
        iv, ciphertext, tag = encrypt_AES_GCM(transaction_data, aes_key)
        enc_time = time.time() - start

        # Sign ciphertext
        signature = sign_data(ciphertext, private_key)

        print("\n--- Encrypted Output ---")
        print("Ciphertext:", ciphertext.hex())
        print("IV:", iv.hex())
        print("Tag:", tag.hex())
        print("Signature:", signature.hex())
        print("Encryption Time: {:.6f} seconds".format(enc_time))

        # Decrypt and verify
        start = time.time()
        try:
            verify_signature(ciphertext, signature, public_key)
            decrypted_data = decrypt_AES_GCM(iv, ciphertext, tag, aes_key)
            print("\n--- Decryption Successful ---")
            print("Decrypted Data:", decrypted_data.decode())
        except (ValueError, TypeError):
            print("Verification or Decryption failed. Data may be tampered.")
        dec_time = time.time() - start
        print("Decryption & Verification Time: {:.6f} seconds".format(dec_time))

        # Simple Performance Comparison Output
        print("\n--- Performance Comparison ---")
        print("Old AES-128-ECB mode lacks IV, Tag, and Auth; vulnerable to pattern analysis.")
        print("New AES-256-GCM mode includes IV, tag, and supports integrity + authenticity.")
        print("GCM also provides protection against tampering (authentication tag).")
        
    except ValueError as e:
        print("Error:", e)
