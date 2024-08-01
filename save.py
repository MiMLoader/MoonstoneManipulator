import secrets
import struct
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def get_password_key(password):
    """Converts a password to a raw key suitable for PBKDF2.

    Args:
        password (str): The password to convert.

    Returns:
        bytes: The raw key.
    """
    return password.encode('utf-8')

def derive_key(password, salt, iterations, key_size):
    """Derives a cryptographic key using PBKDF2.

    Args:
        password (str): The password.
        salt (bytes): The salt for the KDF.
        iterations (int): The number of iterations for the KDF.
        key_size (int): The desired key size in bits.

    Returns:
        bytes: The derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=iterations,
        length=key_size // 8  # Convert key size from bits to bytes
    )
    return kdf.derive(get_password_key(password))

def decrypt_array_buffer(data, password, output_file):
    """Decrypts an array buffer using AES-GCM and saves the output to a file.

    Args:
        data: The encrypted data as a byte string.
        password: The password used for decryption.
        output_file: The path to the output file.
    """

    if len(data) < 33:
        raise ValueError(f"Data too short ({len(data)} bytes)")

    # Extract header information
    reserved_value = data[0]
    if reserved_value != 0:
        raise ValueError(f"Unexpected reserved value {reserved_value}")
    salt = data[1:17]
    iv = data[17:29]
    tag_length = int.from_bytes(data[29:33], byteorder='little')
    ciphertext = data[33:-16]
    authentication_tag = data[-16:]

    # Derive the key with 10000 iterations
    key = derive_key(password, salt, 10000, 256)

    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, authentication_tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Save the decrypted data to a file
    with open(output_file, 'wb') as f:
        f.write(plaintext)

def encrypt_array_buffer(data, password, output_file):
    """Encrypts an array buffer using AES-GCM and saves the output to a file.

    Args:
        data: The data to be encrypted as a byte string.
        password: The password used for encryption.
        output_file: The path to the output file.
    """

    # Generate random values
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)

    # Derive the key with 10000 iterations
    key = derive_key(password, salt, 10000, 256)

    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    tag = encryptor.tag

    # Construct the output buffer
    output = bytearray(1 + len(salt) + len(iv) + 4 + len(ciphertext) + len(tag))
    output[0] = 0  # Reserved value
    output[1:17] = salt
    output[17:29] = iv
    value_to_set = int.from_bytes(b'\x00\x00\x27\x10', byteorder='little')
    output[29:33] = struct.pack('<I', value_to_set)
    output[33:33+len(ciphertext)] = ciphertext
    output[33+len(ciphertext):] = tag

    # Save the encrypted data to a file
    with open(output_file, 'wb') as f:
        f.write(output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt or Encrypt a file using password")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Encryption or decryption mode")
    parser.add_argument("password", help="Password for encryption/decryption")
    parser.add_argument("input_file", help="Path to the encrypted file")
    parser.add_argument("output_file", help="Path to save the decrypted file")

    args = parser.parse_args()

    try:
        with open(args.input_file, 'rb') as f:
            data = f.read()

        if args.mode == "encrypt":
            encrypt_array_buffer(data, args.password, args.output_file)
        elif args.mode == "decrypt":
            decrypt_array_buffer(data, args.password, args.output_file)
        else:
            raise ValueError("Invalid mode")

        print(f"{args.mode.capitalize()}ion successful. Output saved to: {args.output_file}")
    except Exception as e:
        print(f"{args.mode.capitalize()}ion failed: {e}")