import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import secrets
import hmac
import hashlib
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import Type
from argon2.low_level import hash_secret_raw

# Função para derivar chave usando Argon2
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


# Função para criptografar arquivos
def encrypt_file(file_path, password_bytearray):
    try:
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
        messagebox.showinfo("Success", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")


# Função para descriptografar arquivos
# Função para descriptografar arquivos
def decrypt_file(file_path, password_bytearray):
    try:
        # Abrir arquivo criptografado
        with open(file_path, 'rb') as f:
            # Lê o salt (32 bytes)
            salt = f.read(32)
            # Lê o IV (16 bytes)
            iv = f.read(16)
            # Lê o total padding (4 bytes)
            total_padding = int.from_bytes(f.read(4), 'big')
            # Lê o dado criptografado
            encrypted_data = f.read(os.path.getsize(file_path) - 32 - 16 - 4 - 16 - 32)  # Tamanho restante após salt, iv, total_padding, tag_data, hmac_value
            # Lê o tag de autenticação (16 bytes)
            tag_data = f.read(16)
            # Lê o valor de HMAC (32 bytes)
            hmac_value = f.read(32)

        # Derivar chave de criptografia (AES) e chave de verificação (HMAC) a partir da senha
        aes_key, hmac_key, _ = derive_key(password_bytearray, salt)

        # Verificar integridade com HMAC
        expected_hmac = hmac.new(hmac_key, encrypted_data, hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_value, expected_hmac):
            raise ValueError("Incorrect password. Decryption failed.")

        # Descriptografar com AES GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag_data))
        decryptor = cipher.decryptor()

        # Descriptografar os dados
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remover padding
        decrypted_data = decrypted_data[:-total_padding]

        # Definir o caminho do arquivo descriptografado
        if file_path.endswith('.aes'):
            decrypted_file_path = file_path[:-4]  # Remover a extensão ".aes"
        else:
            decrypted_file_path = file_path  # Caso inesperado

        # Salvar o arquivo descriptografado
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        # Excluir o arquivo criptografado com segurança
        secure_delete(file_path)

        messagebox.showinfo("Success", "File decrypted successfully!")

    except ValueError as ve:
        messagebox.showerror("Error", f"Decryption failed: {str(ve)}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")

# Função para excluir arquivo com segurança
def secure_delete(file_path):
    try:
        length = os.path.getsize(file_path)
        with open(file_path, 'wb') as f:  # Usar 'wb' para sobrescrever em modo binário
            for _ in range(3):  # Sobrescrever 3 vezes
                f.seek(0)
                f.write(secrets.token_bytes(length))
        os.remove(file_path)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to securely delete the file: {str(e)}")


# Função para executar ações
def perform_action(action, password_entry, file_entry):
    password = password_entry.get()
    file_path = file_entry.get()
    if not password or not file_path:
        messagebox.showwarning("Input Error", "Please fill in all fields")
        return
    
    password_bytearray = bytearray(password, 'utf-8')
    
    try:
        if action == 'encrypt':
            encrypt_file(file_path, password_bytearray)
        elif action == 'decrypt':
            decrypt_file(file_path, password_bytearray)
        else:
            messagebox.showerror("Action Error", "Invalid action. Use 'encrypt' or 'decrypt'.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Função para configurar o tema escuro
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


# Função para gerar senha de 45 caracteres
def generate_password():
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(chars) for _ in range(45))
    return password


# Função para exibir o teclado virtual
def show_virtual_keyboard():
    keyboard = tk.Toplevel(root)
    keyboard.title("Virtual Keyboard")
    keyboard.geometry("650x350")
    keyboard.resizable(False, False)

    keyboard_buttons = [
        ('1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', 'Backspace'),
        ('q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\\'),
        ('a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', "'", 'Enter'),
        ('z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 'Shift'),
        ('´', '`', '{', '}', ':', '!', '@', '#', '$', '%', '&', '*', '()'),
        ('Space', 'Shift')
    ]

    shift_active = False

    def on_key_press(key):
        current_text = password_entry.get()
        if key == 'Space':
            password_entry.insert(tk.END, ' ')
        elif key == 'Backspace':
            password_entry.delete(len(current_text)-1, tk.END)
        elif key == 'Shift':
            nonlocal shift_active
            shift_active = not shift_active
            update_keyboard()
        elif key == 'Enter':
            password_entry.insert(tk.END, '\n')
        else:
            if shift_active:
                password_entry.insert(tk.END, key.upper())
            else:
                password_entry.insert(tk.END, key)

    def update_keyboard():
        for widget in keyboard.winfo_children():
            widget.destroy()

        # Recriar os botões com base no estado de Shift
        for row_index, row in enumerate(keyboard_buttons):
            for col_index, key in enumerate(row):
                button_text = key
                if shift_active and key.isalpha():
                    button_text = key.upper()
                button = tk.Button(keyboard, text=button_text, width=5, height=2, font=('Helvetica', 12),
                                   command=lambda key=key: on_key_press(key))
                button.grid(row=row_index, column=col_index, padx=5, pady=5)

    # Configurar o tema CLAM DARK
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TButton", background="#444444", foreground="white", font=('Helvetica', 12))
    style.configure("TLabel", foreground="white", background="#2e2e2e")
    keyboard.configure(bg="#2e2e2e")

    update_keyboard()  # Inicializar a tela do teclado

    keyboard.mainloop()



# GUI principal
root = tk.Tk()
root.title("AESCrypt 6.0AK")
root.geometry("650x350")
root.resizable(False, False)

set_dark_theme()

title_label = ttk.Label(root, text="AESCrypt 6.0AK", font=('Helvetica', 16, 'bold'))
title_label.grid(row=0, column=0, columnspan=3, padx=10, pady=(10, 0))

instructions_label = ttk.Label(
    root,
    text="1. Select a file or folder to encrypt or decrypt.\n"
         "2. Enter a password or generate one.\n"
         "3. Click 'Encrypt' or 'Decrypt' to perform the action.\n"
         "4. For batch encryption, select a folder and encrypt all files inside.",
    font=('Helvetica', 12)
)
instructions_label.grid(row=1, column=0, columnspan=3, padx=10, pady=(0, 20))

file_label = ttk.Label(root, text="File/Folder Path:")
file_label.grid(row=2, column=0, padx=10, pady=5, sticky='e')

file_entry = ttk.Entry(root, width=50)
file_entry.grid(row=2, column=1, padx=10, pady=5)

browse_button = ttk.Button(root, text="Browse", command=lambda: file_entry.insert(0, filedialog.askopenfilename()))
browse_button.grid(row=2, column=2, padx=10, pady=5)

password_label = ttk.Label(root, text="Password:")
password_label.grid(row=3, column=0, padx=10, pady=5, sticky='e')

password_entry = ttk.Entry(root, width=50, show="*")
password_entry.grid(row=3, column=1, padx=10, pady=5)

generate_button = ttk.Button(root, text="Generate", command=lambda: password_entry.insert(0, generate_password()))
generate_button.grid(row=3, column=2, padx=10, pady=5)

encrypt_button = ttk.Button(root, text="Encrypt", style="EncryptButton.TButton",
                            command=lambda: perform_action('encrypt', password_entry, file_entry))
encrypt_button.grid(row=4, column=0, padx=10, pady=10)

decrypt_button = ttk.Button(root, text="Decrypt", style="DecryptButton.TButton",
                            command=lambda: perform_action('decrypt', password_entry, file_entry))
decrypt_button.grid(row=4, column=1, padx=10, pady=10)

keyboard_button = ttk.Button(root, text="Virtual Keyboard", command=show_virtual_keyboard)
keyboard_button.grid(row=4, column=2, padx=10, pady=10)

root.mainloop()
