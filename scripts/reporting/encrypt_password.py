from cryptography.fernet import Fernet

# Step 1: Generate key (רק פעם אחת!)
key = Fernet.generate_key()
with open("secret.key", "wb") as key_file:
    key_file.write(key)

# Step 2: Encrypt your Gmail App Password
password = b"nxwt ylrs yegj pcto"
f = Fernet(key)
encrypted = f.encrypt(password)

with open("password.encrypted", "wb") as enc_file:
    enc_file.write(encrypted)

print("✅ Password encrypted and saved.")
