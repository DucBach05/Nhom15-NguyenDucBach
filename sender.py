from Crypto.Cipher import DES3, DES, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
import json
import base64

# Handshake (giả lập)
print("Sender: Hello!")
print("Receiver: Ready!")

# Tải khóa
with open("receiver_public.pem", "rb") as f:
    receiver_pub = RSA.import_key(f.read())
with open("sender_private.pem", "rb") as f:
    sender_priv = RSA.import_key(f.read())

# Tạo session key cho 3DES
session_key = get_random_bytes(24)
iv = get_random_bytes(8)

# Đọc file nhạc
with open("music.mp3", "rb") as f:
    plaintext = f.read()
pad_len = 8 - len(plaintext) % 8
plaintext += bytes([pad_len]) * pad_len
ciphertext = DES3.new(session_key, DES3.MODE_CBC, iv).encrypt(plaintext)

# Metadata
metadata = b"file=song.mp3;copyright=2025 DB"
key_meta = get_random_bytes(8)
meta_pad = 8 - len(metadata) % 8
metadata += bytes([meta_pad]) * meta_pad
meta_cipher = DES.new(key_meta, DES.MODE_ECB).encrypt(metadata)

# Mã hóa session key
rsa_cipher = PKCS1_OAEP.new(receiver_pub, hashAlgo=SHA512)
encrypted_key = rsa_cipher.encrypt(session_key)

# Tính hash
digest = SHA512.new(iv + ciphertext + meta_cipher)

# Ký số
signature = pkcs1_15.new(sender_priv).sign(digest)

# Gói tin
packet = {
    "iv": base64.b64encode(iv).decode(),
    "cipher": base64.b64encode(ciphertext).decode(),
    "meta": base64.b64encode(meta_cipher).decode(),
    "encrypted_key": base64.b64encode(encrypted_key).decode(),
    "hash": base64.b64encode(digest.digest()).decode(),
    "sig": base64.b64encode(signature).decode()
}
with open("packet.json", "w") as f:
    json.dump(packet, f, indent=2)

with open("meta_key.bin", "wb") as f:
    f.write(key_meta)

print("✅ Gửi thành công.")