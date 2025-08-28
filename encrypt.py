import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Given AES key and IV
BASE_AES_KEY = bytes([
    0x1E, 0x3E, 0x4C, 0x6F, 0xD9, 0x12, 0x83, 0x7A,
    0xA4, 0x6E, 0xA0, 0x50, 0x53, 0x28, 0xED, 0x7B,
    0xB2, 0x0E, 0xD2, 0x3B, 0x37, 0x28, 0xA4, 0xEF,
    0x78, 0x22, 0x88, 0x0B, 0xE8, 0xD0, 0xBE, 0x45
])

AES_IV = bytes([0] * 16)  # 16 zero bytes

def encrypt_file(input_file, output_file):
    # Read plaintext from input file
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Add PKCS#7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Create AES cipher
    cipher = Cipher(algorithms.AES(BASE_AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Write ciphertext to output file
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python encrypt.py <input_file>")
        sys.exit(1)
    
    input_filename = sys.argv[1]
    output_filename = input_filename + ".enc"
    
    encrypt_file(input_filename, output_filename)
    print(f"File encrypted successfully. Output: {output_filename}")