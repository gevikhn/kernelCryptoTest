from Crypto.Cipher import AES

key = b"1234567890abcdef"
plaintext = b"hello world!!!!!"

cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(plaintext)
print(ciphertext.hex())
