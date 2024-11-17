import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import secrets
import hmac
import hashlib
import threading
import string
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import Type
from argon2.low_level import hash_secret_raw


def derive_key(password_bytearray, salt=None):
    if salt is None:
        salt = secrets.token_bytes(32)
    password = bytes(password_bytearray)
    master_key = hash_secret_raw(
        password,
        salt,
        time_cost=6,
        memory_cost=2**17,
        parallelism=2,
        hash_len=64,
        type=Type.ID
    )
    aes_key = master_key[:32]
    hmac_key = master_key[32:]
    return aes_key, hmac_key, salt


def encrypt_file(file_path, password_bytearray, progress_bar):
    aes_key, hmac_key, salt = derive_key(password_bytearray)
    iv = secrets.token_bytes(16)

    with open(file_path, 'rb') as f:
        data = f.read()

    file_size = len(data)
    min_padding = max(1048576 - file_size, 0)
    random_bytes_count = secrets.randbelow(256) + 1
    total_padding = min_padding + random_bytes_count
    random_padding = secrets.token_bytes(total_padding)
    data_padded = data + random_padding

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data_padded) + encryptor.finalize()
    tag_data = encryptor.tag

    hmac_value = hmac.new(hmac_key, encrypted_data, hashlib.sha256).digest()

    encrypted_file_path = file_path + '.aes'
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + total_padding.to_bytes(4, 'big') + encrypted_data + tag_data + hmac_value)

    secure_delete(file_path)
    progress_bar['value'] = 100
    progress_bar.update()
    messagebox.showinfo("Success", "File encrypted successfully!")


def decrypt_file(file_path, password_bytearray, progress_bar):
    try:
        with open(file_path, 'rb') as f:
            if os.path.getsize(file_path) < 80:
                raise ValueError("File too small to contain valid encrypted data.")
            
            salt = f.read(32)
            iv = f.read(16)
            total_padding = int.from_bytes(f.read(4), 'big')
            encrypted_data_size = os.path.getsize(file_path) - 32 - 16 - 4 - 16 - 32
            encrypted_data = f.read(encrypted_data_size)
            tag_data = f.read(16)
            hmac_value = f.read(32)
        
        aes_key, hmac_key, _ = derive_key(password_bytearray, salt)

        expected_hmac = hmac.new(hmac_key, encrypted_data, hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_value, expected_hmac):
            raise ValueError("Incorrect password. Decryption failed.")

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag_data))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        decrypted_data = decrypted_data[:-total_padding]

        decrypted_file_path = file_path.replace('.aes', '')
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        progress_bar['value'] = 100
        progress_bar.update()
        messagebox.showinfo("Success", "File decrypted successfully!")

    except ValueError as ve:
        messagebox.showerror("Error", f"Decryption failed: {str(ve)}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")


def secure_delete(file_path):
    with open(file_path, 'r+b') as f:
        length = os.path.getsize(file_path)
        for _ in range(3):
            f.seek(0)
            f.write(secrets.token_bytes(length))
    os.remove(file_path)


def perform_action(action, password_entry, file_entry, progress_bar):
    password = password_entry.get()
    file_path = file_entry.get()
    if not password or not file_path:
        messagebox.showwarning("Input Error", "Please fill in all fields")
        return
    
    password_bytearray = bytearray(password, 'utf-8')
    
    try:
        if action == 'encrypt':
            threading.Thread(target=encrypt_file, args=(file_path, password_bytearray, progress_bar)).start()
        elif action == 'decrypt':
            threading.Thread(target=decrypt_file, args=(file_path, password_bytearray, progress_bar)).start()
        else:
            messagebox.showerror("Action Error", "Invalid action. Use 'encrypt' or 'decrypt'.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def set_dark_theme():
    style = ttk.Style()
    style.theme_use("clam")

    style.configure("TLabel", foreground="white", background="#2e2e2e")
    style.configure("TButton", foreground="white", background="#444444")
    style.configure("TEntry", foreground="white", fieldbackground="#2e2e2e")
    style.configure("TFrame", background="#2e2e2e")
    root.configure(bg="#2e2e2e")

    style.configure("EncryptButton.TButton", background="green")
    style.configure("DecryptButton.TButton", background="red")


def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.config(state='normal')
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)
        file_entry.config(state='readonly')


def browse_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        file_entry.config(state='normal')
        file_entry.delete(0, tk.END)
        file_entry.insert(0, folder_path)
        file_entry.config(state='readonly')


def generate_password():
    length = 45
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)


root = tk.Tk()
root.title("AESCrypt Argon 5.0")
root.geometry("650x350")
root.resizable(False, False)

set_dark_theme()

title_label = ttk.Label(root, text="AESCrypt Argon 5.0", font=('Helvetica', 16, 'bold'))
title_label.grid(row=0, column=0, columnspan=3, padx=10, pady=(10, 0))

instructions_label = ttk.Label(root, text="1. Select a file or folder to encrypt or decrypt.\n"
                                         "2. Enter a password or generate one.\n"
                                         "3. Click 'Encrypt' or 'Decrypt' to perform the action.\n"
                                         "4. For batch encryption, select a folder and encrypt all files inside.", font=('Helvetica', 12))
instructions_label.grid(row=1, column=0, columnspan=3, padx=10, pady=(0, 20))

file_label = ttk.Label(root, text="File/Folder Path:")
file_label.grid(row=2, column=0, padx=10, pady=5, sticky='e')

file_entry = tk.Entry(root, width=50)
file_entry.grid(row=2, column=1, padx=10, pady=5)
file_entry.config(state='readonly')

browse_button = ttk.Button(root, text="Browse", command=browse_file)
browse_button.grid(row=2, column=2, padx=10, pady=5)

password_label = ttk.Label(root, text="Password:")
password_label.grid(row=3, column=0, padx=10, pady=5)

password_entry = ttk.Entry(root, width=50, show="*")
password_entry.grid(row=3, column=1, padx=10, pady=5)

generate_password_button = ttk.Button(root, text="Generate Password", command=generate_password)
generate_password_button.grid(row=3, column=2, padx=10, pady=5)

encrypt_button = ttk.Button(root, text="Encrypt", command=lambda: perform_action('encrypt', password_entry, file_entry, progress_bar), style="EncryptButton.TButton", width=20)
encrypt_button.grid(row=4, column=1, pady=20, sticky='ew', padx=10)

decrypt_button = ttk.Button(root, text="Decrypt", command=lambda: perform_action('decrypt', password_entry, file_entry, progress_bar), style="DecryptButton.TButton", width=20)
decrypt_button.grid(row=5, column=1, pady=20, sticky='ew', padx=10)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
progress_bar.grid(row=6, column=0, columnspan=3, padx=10, pady=10)

root.mainloop()
