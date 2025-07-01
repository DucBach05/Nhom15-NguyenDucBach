from Crypto.PublicKey import RSA

# Khóa người gửi: RSA 2048-bit
sender_key = RSA.generate(2048)
with open("sender_private.pem", "wb") as f:
    f.write(sender_key.export_key())
with open("sender_public.pem", "wb") as f:
    f.write(sender_key.publickey().export_key())

# Khóa người nhận: RSA 2048-bit
receiver_key = RSA.generate(2048)
with open("receiver_private.pem", "wb") as f:
    f.write(receiver_key.export_key())
with open("receiver_public.pem", "wb") as f:
    f.write(receiver_key.publickey().export_key())

print("✅ Đã tạo khóa RSA 2048-bit.")
