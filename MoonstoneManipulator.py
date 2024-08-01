import hashlib
import os
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import secrets
import struct
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

def encrypt_decrypt(mode, input_file, output_file):
    mode = mode_var.get()
    input_file = input_file_entry.get()
    output_file = output_file_entry.get()
    print("processing")
    print(mode)
    print(input_file)
    print(output_file)

    try:
        with open("password.txt", "r") as passwordFile:
            password = passwordFile.read().strip()
        with open(input_file, 'rb') as dataFile:
            data = dataFile.read()

        if mode == "encrypt":
            encrypt_array_buffer(dataFile, password, output_file)
        elif mode == "decrypt":
            decrypt_array_buffer(dataFile, password, output_file)
        else:
            raise ValueError("Invalid mode")

        messagebox.showinfo("Success", f"{mode.capitalize()}ion successful. Output saved to: {output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"{mode.capitalize()}ion failed: {e}")

def password_prompt():
    password_window = tk.Toplevel()
    password_window.title("Moonstone Manipulator Password Entry")
    password_window.geometry("200x200+100+100")
    password_window.title("Enter save file password")

    password_label = tk.Label(password_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(password_window, show="*")
    password_entry.pack()

    def save_password():
        password = password_entry.get()
        # Hash the password for storage
        #hashed_password = hashlib.sha256(password.encode()).hexdigest()
        with open("password.txt", "w") as f:
            f.write(password)
            password_window.destroy()


    save_button = tk.Button(password_window, text="Save", command=save_password)
    save_button.pack()

def create_main_window():
# Create the main window
    root = tk.Tk()
    root.title("Moonstone Manipulator")
    root.geometry("400x300+300+200")

    if not os.path.exists("password.txt"):
        password_prompt()

    # Mode selection
    mode_var = tk.StringVar(value="encrypt")
    encrypt_radio = tk.Radiobutton(root, text="Encrypt", variable=mode_var, value="encrypt")
    decrypt_radio = tk.Radiobutton(root, text="Decrypt", variable=mode_var, value="decrypt")
    encrypt_radio.pack()
    decrypt_radio.pack()

    def select_input_file():
        file_path = filedialog.askopenfilename(filetypes=[("DAT files", "*.dat")])
        input_file_entry.delete(0, tk.END)
        input_file_entry.insert(0, file_path)

    def select_output_file():
        file_path = filedialog.asksaveasfilename(defaultextension=".dat", filetypes=[("DAT files", "*.dat")])
        output_file_entry.delete(0, tk.END)
        output_file_entry.insert(0, file_path)

    # Input file selection
    input_file_label = tk.Label(root, text="Input file:")
    input_file_label.pack()
    input_file_entry = tk.Entry(root)
    input_file_entry.pack()
    input_file_button = tk.Button(root, text="Browse", command=select_input_file)
    input_file_button.pack()

    # Output file selection
    output_file_label = tk.Label(root, text="Output file:")
    output_file_label.pack()
    output_file_entry = tk.Entry(root)
    output_file_entry.pack()
    output_file_button = tk.Button(root, text="Browse", command=select_output_file)
    output_file_button.pack()


    # Start button
    start_button = tk.Button(root, text="Start", command=encrypt_decrypt(mode_var, input_file_entry, output_file_entry))
    start_button.pack()
    root.mainloop()

create_main_window()