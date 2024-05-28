import os
import rsa
import shutil
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

class Sender:
    def file_generate(self):
        message = "This is a secret message."
        with open("sender/file.txt", "wb") as f:
            f.write(message.encode())

    def rsa_generate(self):
        (pub, priv) = rsa.newkeys(2048)
        with open("sender/pub.pem", "wb") as f:
            f.write(pub.save_pkcs1('PEM'))
        with open("sender/priv.pem", "wb") as f:
            f.write(priv.save_pkcs1('PEM'))
    
    def sign_generate(self):
        # sign the file with RSA private key
        priv = rsa.PrivateKey.load_pkcs1(open("sender/priv.pem").read())
        message = open("sender/file.txt", "rb").read()
        signature = rsa.sign(message, priv, 'SHA-256')
        with open("sender/signed_file.txt", "wb") as f:
            f.write(message)
            f.write(b'\n---SIGNATURE---\n')
            f.write(signature)
    
    def encrypt_files(self):
        # encrypt the signed file with AES
        aes_key =  get_random_bytes(32)
        cipher = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher.iv

        with open("sender/signed_file.txt", "rb") as f:
            contents = f.read()
        ciphertext = cipher.encrypt(pad(contents, AES.block_size))
        with open("sender/encrypted_file.bin", "wb") as f:
            f.write(iv+ciphertext)
        
        print("AES key:", aes_key)
        # encrypt the AES key with receiver's public key
        receiver_pub = rsa.PublicKey.load_pkcs1(open("sender/receiver_pub.pem").read())
        encrypted_aes_key = rsa.encrypt(aes_key, receiver_pub)

        with open("sender/encrypted_aes_key.bin", "wb") as f:
            f.write(encrypted_aes_key)

    def send_files(self):
        # send RSA public key to verifier
        self.cp_rename("sender/pub.pem", "verifier", "sender_pub.pem")
        # send encrypted AES key to verifier
        self.cp_rename("sender/encrypted_aes_key.bin", "verifier", "sender_encrypted_aes_key.bin")
        # send encrypted file to receiver
        self.cp_rename("sender/encrypted_file.bin", "receiver", "sender_encrypted_file.bin")

    @staticmethod
    def cp_rename(src, dst, new_name):
        dst = os.path.join(dst, new_name)
        shutil.copy2(src, dst)
    
    def decrypt_random(self):
        ciphertext = open("sender/verifier_encrypted_random_message.bin", "rb").read()
        priv = rsa.PrivateKey.load_pkcs1(open("sender/priv.pem").read())
        message = rsa.decrypt(ciphertext, priv)
        with open("sender/decrypted_random_message.txt", "wb") as f:
            f.write(message)
        
        Sender.cp_rename("sender/decrypted_random_message.txt", "verifier", "sender_decrypted_random_message.txt")