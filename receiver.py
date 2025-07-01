from Crypto.Cipher import DES3, DES, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import json
import base64

# Tải khóa
with open("receiver_private.pem", "rb") as f:
    receiver_priv = RSA.import_key(f.read())
with open("sender_public.pem", "rb") as f:
    sender_pub = RSA.import_key(f.read())

# Tải gói tin
with open("packet.json", "r") as f:
    packet = json.load(f)

iv = base64.b64decode(packet["iv"])
ciphertext = base64.b64decode(packet["cipher"])
meta_cipher = base64.b64decode(packet["meta"])
encrypted_key = base64.b64decode(packet["encrypted_key"])
digest_received = base64.b64decode(packet["hash"])
sig = base64.b64decode(packet["sig"])

# Kiểm tra toàn vẹn
digest = SHA512.new(iv + ciphertext + meta_cipher)
if digest.digest() != digest_received:
    print("Lỗi toàn vẹn (HASH)")
    print("NACK")
    exit()

# Kiểm tra chữ ký
try:
    pkcs1_15.new(sender_pub).verify(digest, sig)
except:
    print("Sai chữ ký số")
    print("NACK")
    exit()

# Giải mã khóa phiên
session_key = PKCS1_OAEP.new(receiver_priv, hashAlgo=SHA512).decrypt(encrypted_key)

# Giải mã nhạc
plain_padded = DES3.new(session_key, DES3.MODE_CBC, iv).decrypt(ciphertext)
pad_len = plain_padded[-1]
plaintext = plain_padded[:-pad_len]
with open("song_decrypted.mp3", "wb") as f:
    f.write(plaintext)

# Giải mã metadata
with open("meta_key.bin", "rb") as f:
    key_meta = f.read()
metadata_padded = DES.new(key_meta, DES.MODE_ECB).decrypt(meta_cipher)
meta = metadata_padded.rstrip(bytes([metadata_padded[-1]]))
print("✅ Metadata:", meta.decode())

print("✅ Nhận thành công. Gửi ACK.")
