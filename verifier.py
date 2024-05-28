import rsa
import random
import string
from sender import Sender

class Verifier:
    def zkp(self):
        # generate a random message
        Verifier.random_generate()

        # encrypt the random message with sender's public key
        pub = rsa.PublicKey.load_pkcs1(open("verifier/sender_pub.pem").read())
        message = open("verifier/random_message.txt", "rb").read()
        ciphertext = rsa.encrypt(message, pub)
        with open("verifier/encrypted_random_message.bin", "wb") as f:
            f.write(ciphertext)

        # send the encrypted random message to sender
        Sender.cp_rename("verifier/encrypted_random_message.bin", "sender", "verifier_encrypted_random_message.bin")

    def random_generate():
        message = ''.join(random.choices(string.digits, k=20))
        with open("verifier/random_message.txt", "wb") as f:
            f.write(message.encode())

    def verify(self):
        with open("verifier/sender_decrypted_random_message.txt", "rb") as f:
            sender_message = f.read()
        with open("verifier/random_message.txt", "rb") as f:
            verifier_message = f.read()

        if sender_message == verifier_message:
            return True
        else:
            return False
        
    def send_keys(self):
        # send encrypted AES key to receiver
        Sender.cp_rename("verifier/sender_encrypted_aes_key.bin", "receiver", "verifier_encrypted_aes_key.bin")
        # send sender's RSA public key to receiver
        Sender.cp_rename("verifier/sender_pub.pem", "receiver", "sender_pub.pem")