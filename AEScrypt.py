import tkinter as tk
from tkinter import filedialog, messagebox
import os
import secrets
import ctypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import tkinter.ttk as ttk

def derive_key(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=500000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_file(file_path, password):
    key, salt = derive_key(password)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        data = f.read()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    hmac_value = h.finalize()

    encrypted_file_path = file_path + '.aes'
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data + hmac_value)

    ctypes.memset(ctypes.cast(ctypes.create_string_buffer(password.encode()), ctypes.POINTER(ctypes.c_char)), 0, len(password))

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        file_size = os.path.getsize(file_path)
        hmac_size = 32
        encrypted_data_size = file_size - 16 - 16 - hmac_size
        
        encrypted_data = f.read(encrypted_data_size)
        hmac_value = f.read(hmac_size)

    key, _ = derive_key(password, salt)

    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    try:
        computed_hmac = h.finalize()
        if computed_hmac != hmac_value:
            raise ValueError("HMAC verification failed: Signature did not match digest.")
    except Exception as e:
        raise ValueError(f"HMAC verification failed: {e}")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()

    decrypted_file_path = file_path.replace('.aes', '')
    with open(decrypted_file_path, 'wb') as f:
        f.write(data)

    ctypes.memset(ctypes.cast(ctypes.create_string_buffer(password.encode()), ctypes.POINTER(ctypes.c_char)), 0, len(password))

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
    import random
    import string
    password_length = 32
    allowed_chars = string.ascii_letters + string.digits + "!@#$%&*()[]{},."
    password = ''.join(random.choice(allowed_chars) for _ in range(password_length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

def perform_action(action):
    password = password_entry.get()
    file_path = file_entry.get()
    if not password or not file_path:
        messagebox.showwarning("Input Error", "Please fill in all fields")
        return
    if not os.path.isabs(file_path):
        messagebox.showerror("File Error", "The file path must be absolute.")
        return
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

def set_dark_theme():
    root.config(bg='#2e2e2e')
    style = ttk.Style()
    style.theme_use("clam")
    style.configure('TLabel', background='#2e2e2e', foreground='white')
    style.configure('TButton', background='#444', foreground='white', font=('Helvetica', 12, 'bold'), padding=10)
    style.map('TButton', background=[('active', '#555')])

root = tk.Tk()
root.title("AEScrypt v2.0")
root.resizable(False, False)

set_dark_theme()

title_label = ttk.Label(root, text="AEScrypt v2.0", font=('Helvetica', 16, 'bold'))
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
