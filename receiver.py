import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sender import Sender


class Receiver:
    def rsa_generate(self):
        (pub, priv) = rsa.newkeys(2048)
        with open("receiver/pub.pem", "wb") as f:
            f.write(pub.save_pkcs1('PEM'))
        with open("receiver/priv.pem", "wb") as f:
            f.write(priv.save_pkcs1('PEM'))
        Sender.cp_rename("receiver/pub.pem", "sender", "receiver_pub.pem")

    def decrypt(self):
        encrypted_aes_key = open("receiver/verifier_encrypted_aes_key.bin", "rb").read()
        sender_pub = open("receiver/sender_pub.pem", "rb").read()
        sender_pub = rsa.PublicKey.load_pkcs1(sender_pub)
        receiver_priv = open("receiver/priv.pem", "rb").read()
        receiver_priv = rsa.PrivateKey.load_pkcs1(receiver_priv)

        aes_key = rsa.decrypt(encrypted_aes_key, receiver_priv)
        print("AES key:", aes_key)
        
        with open("receiver/sender_encrypted_file.bin", "rb") as f:
            iv = f.read(16)
            ciphertext = f.read()
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        with open("receiver/decrypted_file.txt", "wb") as f:
            f.write(plaintext)

        message_part, signature_part, = plaintext.split(b'\n---SIGNATURE---\n', 1)
        try:
            rsa.verify(message_part, signature_part, sender_pub)
            print("Signature verified")
        except:
            print("Signature not verified")
        
        print("Decrypted file:", message_part.decode())

