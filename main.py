import os
from sender import Sender
from receiver import Receiver
from verifier import Verifier

os.makedirs("sender", exist_ok=True)
os.makedirs("receiver", exist_ok=True)
os.makedirs("verifier", exist_ok=True)

def main():
    sender = Sender()
    receiver = Receiver()
    verifier = Verifier()
    
    # sender generates a file
    sender.file_generate()

    # sender generates a RSA key pair
    sender.rsa_generate()

    # receiver generates a RSA key pair
    # receiver: pub.pem -> sender
    receiver.rsa_generate()

    # sender signs the file with sender's private key
    sender.sign_generate()

    # sender encrypts the file with AES and encrypts the AES key with receiver's public key,
    sender.encrypt_files()

    # sender: encrypted_file.bin -> receiver
    # sender: pub.pem -> verifier
    # sender: encrypted_aes_key.bin -> verifier
    sender.send_files()

    # verifier generate a random message and encrypt it
    # verifier: encrypted_random_message.bin -> sender
    verifier.zkp()

    # sender decrypt the random message
    # sender: decrypted_random_message.txt -> verifier
    sender.decrypt_random()

    # verifier verify the sender's random message
    # if random message == sender's decrypted random message, then the transfer is safe
    is_safe = verifier.verify()
    print("Is safe?", is_safe)
    if is_safe:
        # verifier: sender_encrypted_aes_key.bin -> receiver
        # verifier: sender_pub.pem -> receiver
        verifier.send_keys()

        # receiver decrypt the AES key and decrypt the file
        receiver.decrypt()

if __name__ == "__main__":
    main()