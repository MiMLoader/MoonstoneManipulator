import hashlib
import os
import shutil
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import secrets
import struct
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backup_folder = "Backups"

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

    try:
        with open(output_file, 'wb') as f:
            f.write(plaintext)
    except OSError as e:
        raise OSError(f"Error writing to output file: {e}")

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
    try:
        with open(output_file, 'wb') as f:
            f.write(output)
    except OSError as e:
        raise OSError(f"Error writing to output file: {e}")
    
def check_password(password):
    correct_hash = "a1feb661ae01073f17f5b12f16ed2082deca0ff4bdc761906bf431101917332f"
    input_hash = hashlib.sha256(password.encode()).hexdigest()
    if input_hash != correct_hash:
        raise ValueError("Incorrect save file password.")
        return
    return

def copy_file(src, dst, backup_folder):
    """Copies a file to a destination, creating a numbered backup in a specified folder.

    Args:
      src (str): Path to the source file.
      dst (str): Path to the destination file.
      backup_folder (str): Path to the backup folder.
    """
    try:
      # Create the backup folder if it doesn't exist
      os.makedirs(backup_folder, exist_ok=True)

      # Generate backup file path with incremental number
      base_name, ext = os.path.splitext(os.path.basename(src))
      backup_number = 1
      backup_file = os.path.join(backup_folder, f"{base_name}_{backup_number}{ext}")
      while os.path.exists(backup_file):
          backup_number += 1
          backup_file = os.path.join(backup_folder, f"{base_name}_{backup_number}{ext}")

      shutil.copy2(src, backup_file)
    except OSError as e:
      raise OSError(f"Error copying file: {e}")


def encrypt_decrypt(mode, input_file, output_file):
    if mode not in ["encrypt", "decrypt"]:
        messagebox.showerror("Error", "Invalid mode selected")
        return
    try:
        with open("password.txt", "r") as passwordFile:
            password = passwordFile.read().strip()
            check_password(password)
        with open(input_file, 'rb') as dataFile:
            data = dataFile.read()
        copy_file(input_file, input_file + ".bak", backup_folder)

        if mode == "encrypt":
            encrypt_array_buffer(data, password, output_file)
        elif mode == "decrypt":
            decrypt_array_buffer(data, password, output_file)
        else:
            raise ValueError("Invalid mode")

        messagebox.showinfo("Success", f"{mode.capitalize()}ion successful. Output saved to: {output_file}")
    except Exception as e:
        messagebox.showerror("Error", f"{mode.capitalize()}ion failed: {e}")

def first_time_prompt():
    first_time_window = tk.Tk()
    first_time_window.title("Welcome to Moonstone Manipulator")
    first_time_window.geometry("450x300+200+200")  # Adjust size as needed

    # Large title
    title_label = tk.Label(first_time_window, text="Moonstone Manipulator", font=("Arial", 16, "bold"), fg="blue")
    title_label.pack()

    author_label = tk.Label(first_time_window, text="Author: SassyCultist  Team: MiMLoader")
    author_label.pack()

    version_label = tk.Label(first_time_window, text="Version 0.2")
    version_label.pack()

    # Warning
    warning_label = tk.Label(first_time_window, text="Disclaimer: You can ruin your save with this tool. Proceed at your own risk.")
    warning_label.pack()

    # Password Hint
    hint_label = tk.Label(first_time_window, text="Save file password is located in package.nw\\scripts\\c3runtime.js near NWJS Enc")
    hint_label.pack()

    password_label = tk.Label(first_time_window, text="Save file password:")
    password_label.pack()
    password_entry = tk.Entry(first_time_window)
    password_entry.pack()
    password_clear = tk.Button(first_time_window, text="Clear", command=lambda: clear_entry(password_entry))
    password_clear.pack()

    def save_password():
        password = password_entry.get()
        check_password(password)
        with open("password.txt", "a") as passwordFile:
            passwordFile.write(password)
            passwordFile.flush()
            first_time_window.destroy()
            create_main_window()


    save_button = tk.Button(first_time_window, text="Save", command=save_password)
    save_button.pack()
    first_time_window.mainloop()

def clear_entry(entry):
    entry.delete(0,tk.END)

def delete_folder(folder):
    if not os.path.exists(folder):
        return 0
    files_deleted = 0
    for file in os.listdir(folder):
        file_path = os.path.join(folder, file)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
                files_deleted += 1
        except OSError as e:
            print(f"Error deleting file: {file_path}. Reason: {e}")
    return files_deleted

def confirm_delete_backups():
    """Prompts the user to confirm deletion of backups.

    Args:
        backup_folder (str): Path to the backup folder.
    """

    confirmation = messagebox.askyesno("Confirm", f"Are you sure you want to delete all backups in {backup_folder}?")
    if confirmation:
        try:
            num_deleted = delete_folder(backup_folder)
            messagebox.showinfo("Success", f"{num_deleted} files deleted successfully.")
        except OSError as e:
            messagebox.showerror("Error", f"Error deleting backups: {e}")

def create_main_window():
# Create the main window
    root = tk.Tk()
    root.title("Moonstone Manipulator")
    root.geometry("400x350+300+200")

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
    input_file_entry = tk.Entry(root, width=50)
    input_file_entry.pack()
    input_file_clear = tk.Button(root, text="Clear", command=lambda: clear_entry(input_file_entry))
    input_file_clear.pack()
    input_file_button = tk.Button(root, text="Browse", command=select_input_file)
    input_file_button.pack()

    # Output file selection
    output_file_label = tk.Label(root, text="Output file:")
    output_file_label.pack()
    output_file_entry = tk.Entry(root, width=50)
    output_file_entry.pack()
    output_file_button = tk.Button(root, text="Browse", command=select_output_file)
    output_file_button.pack()
    output_file_clear = tk.Button(root, text="Clear", command=lambda: clear_entry(output_file_entry))
    output_file_clear.pack()

    # Start button
    start_button = tk.Button(root, text="Start", command= lambda: encrypt_decrypt(mode_var.get(), input_file_entry.get(), output_file_entry.get()))
    start_button.pack()

    # Delete backups button
    delete_backups_button = tk.Button(root, text="Delete Backups", command=confirm_delete_backups)
    delete_backups_button.pack()

    root.mainloop()

if not os.path.exists("password.txt"):
    first_time_prompt()
else:
    create_main_window()