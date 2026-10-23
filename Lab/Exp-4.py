import base64
import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key():
    """Generate a fresh 256-bit encryption key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_message(message, key):
    """
    Encrypt a message using AES-GCM.

    The nonce is public and can be transmitted with
    the ciphertext. The key must remain secret.
    """
    aes = AESGCM(key)

    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    return nonce, ciphertext


def decrypt_message(nonce, ciphertext, key):
    """Decrypt and authenticate a received message."""
    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")


def main():
    print("=" * 55)
    print("SECURE COMMUNICATION DEMONSTRATION")
    print("=" * 55)

    message = input("\nEnter a message to send: ")

    if not message:
        print("Error: Message cannot be empty.")
        return

    # Shared key for this local demonstration.
    key = generate_key()

    print("\nSender:")
    print("Original message:", message)

    nonce, ciphertext = encrypt_message(message, key)

    # Simulate transmission using Base64-encoded data.
    packet = {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(
            ciphertext
        ).decode("ascii")
    }

    print("\nTransmitted packet:")
    print(packet)

    print("\nInterceptor:")
    print("Intercepted ciphertext:", packet["ciphertext"])
    print("The plaintext is not directly visible.")

    print("\nAuthorized receiver:")

    received_nonce = base64.b64decode(packet["nonce"])
    received_ciphertext = base64.b64decode(
        packet["ciphertext"]
    )

    try:
        recovered_message = decrypt_message(
            received_nonce,
            received_ciphertext,
            key
        )

        print("Decrypted message:", recovered_message)

    except InvalidTag:
        print("Authentication failed.")

    # Demonstrate tampering detection.
    print("\nTampering test:")

    modified = bytearray(received_ciphertext)
    modified[0] ^= 1

    try:
        decrypt_message(
            received_nonce,
            bytes(modified),
            key
        )

        print("Unexpected result: Modified data was accepted.")

    except InvalidTag:
        print("Modified ciphertext rejected successfully.")

    # Demonstrate wrong-key rejection.
    print("\nWrong-key test:")

    wrong_key = generate_key()

    try:
        decrypt_message(
            received_nonce,
            received_ciphertext,
            wrong_key
        )

        print("Unexpected result: Wrong key was accepted.")

    except InvalidTag:
        print("Incorrect key rejected successfully.")


if __name__ == "__main__":
    main()
