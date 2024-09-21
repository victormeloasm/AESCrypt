import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import secrets
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import Type
from argon2.low_level import hash_secret_raw
import string
import ctypes

def derive_key(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hash_secret_raw(
        password.encode(),
        salt,
        time_cost=2,
        memory_cost=2**16,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )
    return key, salt

def encrypt_file(file_path, password):
    key, salt = derive_key(password)
    iv = secrets.token_bytes(16)

    with open(file_path, 'rb') as f:
        data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=None)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    tag_data = encryptor.tag

    hmac_value = hmac.new(key, encrypted_data, hashlib.sha256).digest()

    encrypted_file_path = file_path + '.aes'
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data + tag_data + hmac_value)

    try:
        secure_delete(file_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete the original file: {str(e)}")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data_size = os.path.getsize(file_path) - 16 - 16 - 16 - 32
        encrypted_data = f.read(encrypted_data_size)
        tag_data = f.read(16)
        hmac_value = f.read(32)

    key, _ = derive_key(password, salt)

    expected_hmac = hmac.new(key, encrypted_data, hashlib.sha256).digest()
    if not hmac.compare_digest(hmac_value, expected_hmac):
        raise ValueError("HMAC verification failed. The data may have been altered.")

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag_data), backend=None)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    decrypted_file_path = file_path.replace('.aes', '')
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

def secure_delete(file_path):
    with open(file_path, 'r+b') as f:
        length = os.path.getsize(file_path)
        f.seek(0)
        f.write(secrets.token_bytes(length))
    os.remove(file_path)

def encrypt_folder(folder_path, password):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, password)
    messagebox.showinfo("Success", f"All files in {folder_path} have been encrypted.")

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.config(state=tk.NORMAL)
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)
        file_entry.config(state='readonly')

def browse_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        file_entry.config(state=tk.NORMAL)
        file_entry.delete(0, tk.END)
        file_entry.insert(0, folder_path)
        file_entry.config(state='readonly')

def generate_password():
    password_length = 32
    allowed_chars = string.ascii_letters + string.digits + "!@#$%&*()[]{},."
    password = ''.join(secrets.choice(allowed_chars) for _ in range(password_length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

def clear_memory(password_bytes):
    length = len(password_bytes)
    ctypes.memset(id(password_bytes), 0, length)

def perform_action(action):
    password = password_entry.get()
    file_path = file_entry.get()
    if not password or not file_path:
        messagebox.showwarning("Input Error", "Please fill in all fields")
        return
    if not os.path.isabs(file_path):
        messagebox.showerror("File Error", "The file path must be absolute.")
        return
    password_bytes = password.encode()
    try:
        if action == 'encrypt':
            if os.path.isdir(file_path):
                encrypt_folder(file_path, password)
            else:
                encrypt_file(file_path, password)
                messagebox.showinfo("Success", f"File encrypted and saved to {file_path}.aes")
        elif action == 'decrypt':
            decrypt_file(file_path, password)
            messagebox.showinfo("Success", f"File decrypted and saved to {file_path.replace('.aes', '')}")
        else:
            messagebox.showerror("Action Error", "Invalid action. Use 'encrypt' or 'decrypt'.")
    except Exception as e:
        messagebox.showerror("Error", str(e))
    finally:
        clear_memory(password_bytes)

def set_dark_theme():
    root.config(bg='#2e2e2e')
    style = ttk.Style()
    style.theme_use("clam")
    style.configure('TLabel', background='#2e2e2e', foreground='white')
    style.configure('TButton', background='#444', foreground='white', font=('Helvetica', 12, 'bold'), padding=10)
    style.map('TButton', background=[('active', '#555')])

root = tk.Tk()
root.title("AESCrypt v3.5 Argon")
root.resizable(False, False)

set_dark_theme()

title_label = ttk.Label(root, text="AESCrypt v3.5 Argon", font=('Helvetica', 16, 'bold'))
title_label.grid(row=0, column=0, columnspan=3, padx=10, pady=(10, 0))

instructions_label = ttk.Label(root, text="1. Select a file or folder to encrypt or decrypt.\n"
                                         "2. Enter a password or generate one.\n"
                                         "3. Click 'Encrypt' or 'Decrypt' to perform the action.\n"
                                         "4. For batch encryption, select a folder and encrypt all files inside.", font=('Helvetica', 12))
instructions_label.grid(row=1, column=0, columnspan=3, padx=10, pady=(0, 20))

ttk.Label(root, text="File/Folder Path:").grid(row=2, column=0, padx=10, pady=10, sticky='e')
file_entry = tk.Entry(root, width=50)
file_entry.grid(row=2, column=1, padx=10, pady=10)
file_entry.config(state='readonly')
ttk.Button(root, text="Browse File", command=browse_file).grid(row=2, column=2, padx=10, pady=10)
ttk.Button(root, text="Browse Folder", command=browse_folder).grid(row=3, column=2, padx=10, pady=10)

ttk.Label(root, text="Password:").grid(row=3, column=0, padx=10, pady=10, sticky='e')
password_entry = tk.Entry(root, width=50)
password_entry.grid(row=3, column=1, padx=10, pady=10)
ttk.Button(root, text="Generate Password", command=generate_password).grid(row=4, column=2, padx=10, pady=10)

ttk.Button(root, text="Encrypt", command=lambda: perform_action('encrypt')).grid(row=4, column=0, padx=10, pady=10)
ttk.Button(root, text="Decrypt", command=lambda: perform_action('decrypt')).grid(row=4, column=1, padx=10, pady=10)

root.mainloop()
