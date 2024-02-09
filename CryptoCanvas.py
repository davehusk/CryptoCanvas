import time
import random
import binascii
import os
import base64
import mpmath
import matplotlib.pyplot as plt
import numpy as np
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
import binascii
import secrets

# Utility functions

def to_bytes(integer, length):
    """Convert integer to bytes."""
    return integer.to_bytes(length, byteorder='big', signed=False)

def xor_bytes(ba1, ba2):
    """XOR two byte arrays."""
    return bytes([x ^ y for x, y in zip(ba1, ba2)])

# Functions to encrypt and decrypt using AES
def aes_encrypt_decrypt(data, key):
    """Encrypt and decrypt data using AES."""
    iv = os.urandom(16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    # Encrypt
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Decrypt
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

    return encrypted, decrypted.decode()

# Functions to encrypt and decrypt using PiEncrypt
def piencrypt_encrypt_decrypt(data, pi_digits):
    """Encrypt and decrypt data using PiEncrypt."""
    data_binary = ''.join(format(ord(c), '08b') for c in data)
    block_size = 8
    data_blocks = [data_binary[i:i+block_size] for i in range(0, len(data_binary), block_size)]

    master_key = random.randint(0, 9999)

    encrypted_blocks, decrypted_blocks = [], []

    for i, block in enumerate(data_blocks):
        index = (master_key + i) % len(pi_digits)
        key_segment = format(int(pi_digits[index]), '04b')

        encrypted_block = format(int(block, 2) ^ int(key_segment, 2), '08b')
        encrypted_blocks.append(encrypted_block)

        decrypted_block = format(int(encrypted_block, 2) ^ int(key_segment, 2), '08b')
        decrypted_blocks.append(decrypted_block)

    encrypted_message = ''.join(encrypted_blocks)
    decrypted_message = ''.join(chr(int(block, 2)) for block in decrypted_blocks)

    return encrypted_message, decrypted_message

# Function to generate a Fibonacci sequence up to a given length
def generate_fibonacci_key(max_length):
    """Generate a Fibonacci sequence up to a given length."""
    fib_sequence = [0, 1]
    for i in range(2, max_length):
        fib_sequence.append(fib_sequence[i-1] + fib_sequence[i-2])
    return fib_sequence

# Function to encrypt a message using a Fibonacci sequence as the key
def encrypt_message(message, key):
    """Encrypt a message using a Fibonacci sequence as the key."""
    encrypted = ""
    for i, char in enumerate(message):
        encrypted += chr((ord(char) + key[i % len(key)]) % 128)
    return encrypted

# Function to decrypt a message using a Fibonacci sequence as the key
def decrypt_message(encrypted_message, key):
    """Decrypt a message using a Fibonacci sequence as the key."""
    decrypted = ""
    for i, char in enumerate(encrypted_message):
        decrypted += chr((ord(char) - key[i % len(key)]) % 128)
    return decrypted

# Function to generate a unique and novel base64-encoded image
def generate_unique_image():
    """Generate a blank and new base64-encoded image."""
    # Create a blank image
    width, height = 100, 100
    blank_image = np.zeros((width, height, 3), dtype=np.uint8)

    # Save the blank image
    blank_image_path = "blank_image.png"
    plt.imsave(blank_image_path, blank_image)

    # Convert the image to base64
    with open(blank_image_path, "rb") as image_file:
        blank_image_data = base64.b64encode(image_file.read()).decode("utf-8")

    # Clean up: remove the temporary image file
    os.remove(blank_image_path)

    return blank_image_data

# Function to hide an encrypted image inside another image using LSB
def hide_image(cover_image_path, encrypted_image):
    """Hide an encrypted image inside another image using LSB."""
    cover_image = plt.imread(cover_image_path)

    # Flatten the encrypted image
    flat_encrypted_image = np.array([ord(c) for c in encrypted_image], dtype=np.uint8)

    # Embed the encrypted image in the LSB of the cover image
    cover_image.flatten()[::2] &= ~1
    cover_image.flatten()[::2] |= flat_encrypted_image & 1

    return cover_image

# Function to extract the hidden image from the cover image
def extract_hidden_image(hidden_image):
    """Extract the hidden image from the cover image."""
    # Extract the LSBs of the hidden image
    extracted_image = hidden_image.flatten().copy()
    extracted_image[extracted_image > 0] = 1
    extracted_image[extracted_image == 0] = 0

    # Convert the extracted bits back to characters
    extracted_image_chars = "".join(chr(sum(extracted_image[i:i+8])) for i in range(0, len(extracted_image), 8))

    return extracted_image_chars

def run_example():
    run_example()
    # Generate a unique base64-encoded image as the key
    unique_image_key = generate_unique_image()

    # Get the first 10,000 digits of π
    pi_digits = str(mpmath.pi * 10**10000)[2:]
    # Remove the exponentiation character 'e'
    pi_digits = "".join(c for c in pi_digits if c.isdigit())

    # Test data
    data_to_encrypt = "Hello World!"
    print(f"Data to Encrypt: {data_to_encrypt}\n")

    # AES Encryption and Decryption
    key = secrets.token_bytes(16)
    encrypted, decrypted = aes_encrypt_decrypt(data_to_encrypt, key)
    print(f"AES Encrypted: {binascii.hexlify(encrypted)}\n")
    print(f"AES Decrypted: {decrypted}\n")

    # PiEncrypt Encryption and Decryption
    pi_encrypted, pi_decrypted = piencrypt_encrypt_decrypt(data_to_encrypt, pi_digits)
    print(f"PiEncrypt Encrypted: {pi_encrypted}\n")
    print(f"PiEncrypt Decrypted: {pi_decrypted}\n")

    # Fibonacci Key Encryption and Decryption
    fib_encrypted = encrypt_message(data_to_encrypt, generate_fibonacci_key(1000))
    fib_decrypted = decrypt_message(fib_encrypted, generate_fibonacci_key(1000))
    print(f"Fibonacci Key Encrypted: {fib_encrypted}\n")
    print(f"Fibonacci Key Decrypted: {fib_decrypted}\n")

    # Unique Image Key Encryption and Decryption
    encrypted_portion = encrypt_message(unique_image_key[:500], generate_fibonacci_key(1000))
    decrypted_portion = decrypt_message(encrypted_portion, generate_fibonacci_key(1000))
    print(f"Original Portion: {unique_image_key[:500]}\n")
    print(f"Encrypted Portion: {encrypted_portion}\n")
    print(f"Decrypted Portion: {decrypted_portion}\n")

if __name__ == "__main__":
    run_example()
