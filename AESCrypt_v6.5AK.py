import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import secrets
import hmac
import threading
import hashlib
import ctypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2.low_level import hash_secret_raw
from argon2 import Type

# Função para sanitizar o caminho do arquivo
def sanitize_filepath(file_path):
    return os.path.normpath(file_path)

# Função para apagar dados de memória de forma segura
def secure_erase_memory(data):
    try:
        if isinstance(data, (bytearray, memoryview)):
            length = len(data)
            random_data = secrets.token_bytes(length)
            buf = (ctypes.c_char * length).from_buffer(data)
            for i in range(length):
                buf[i] = random_data[i]
            ctypes.memset(buf, 0, length)
        else:
            raise TypeError(f"Data must be a mutable object like bytearray or memoryview, but got {type(data)}.")
    except (BufferError, TypeError) as e:
        raise ValueError(f"Cannot securely erase memory: {str(e)}") from e

# Função para criptografar um arquivo grande com multithreading
def encrypt_large_file(file_path, password_bytearray, block_size=1048576):
    def process_block(chunk, aes_key, iv):
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()
        return encrypted_chunk, encryptor.tag, secrets.token_bytes(16)

    def encryption_worker(input_file, output_file, aes_key, hmac_key, iv, salt):
        try:
            hmac_input = b""
            with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                f_out.write(salt)
                f_out.write(iv)
                while chunk := f_in.read(block_size):
                    if len(chunk) < block_size:
                        padding = (block_size - len(chunk))
                        chunk += bytes([0] * padding)
                    encrypted_chunk, tag, iv = process_block(chunk, aes_key, iv)
                    hmac_input += tag + encrypted_chunk
                    f_out.write(tag)
                    f_out.write(encrypted_chunk)
                hmac_value = hmac.new(hmac_key, salt + hmac_input, hashlib.sha256).digest()
                f_out.write(hmac_value)

            secure_erase_memory(bytearray(hmac_input))
            messagebox.showinfo("Success", f"File encrypted successfully: {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Error encrypting file: {str(e)}")

    try:
        sanitized_file_path = sanitize_filepath(file_path)
        if not os.path.exists(sanitized_file_path):
            messagebox.showerror("File Error", f"File not found: {sanitized_file_path}")
            return

        salt = secrets.token_bytes(32)
        aes_key, hmac_key, _ = derive_key(password_bytearray, salt)
        secure_erase_memory(password_bytearray)

        encrypted_file_path = f"{sanitized_file_path}.aes"
        initial_iv = secrets.token_bytes(16)

        encryption_thread = threading.Thread(
            target=encryption_worker,
            args=(sanitized_file_path, encrypted_file_path, aes_key, hmac_key, initial_iv, salt),
        )
        encryption_thread.start()

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Função para criptografar arquivos pequenos (comum)
def encrypt_file(file_path, password_bytearray):
    try:
        sanitized_file_path = sanitize_filepath(file_path)
        if not os.path.exists(sanitized_file_path):
            messagebox.showerror("File Error", f"The file does not exist: {sanitized_file_path}")
            return

        salt = secrets.token_bytes(32)
        aes_key, hmac_key, _ = derive_key(password_bytearray, salt)
        secure_erase_memory(password_bytearray)

        with open(sanitized_file_path, 'rb') as f:
            file_data = f.read()

        total_padding = (1048576 - len(file_data) % 1048576) % 1048576
        padded_data = file_data + bytes([0] * total_padding)

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        encryptor = cipher.encryptor()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        tag = encryptor.tag

        hmac_input = salt + iv + tag + encrypted_data
        hmac_value = hmac.new(hmac_key, hmac_input, hashlib.sha256).digest()

        encrypted_file_path = f"{sanitized_file_path}.aes"
        with open(encrypted_file_path, 'wb') as f:
            f.write(salt)
            f.write(iv)
            f.write(tag)
            f.write(hmac_value)
            f.write(encrypted_data)

        secure_erase_memory(bytearray(file_data))
        secure_erase_memory(bytearray(padded_data))
        secure_erase_memory(bytearray(encrypted_data))

        secure_delete(sanitized_file_path)

        messagebox.showinfo("Success", "File encrypted and original file securely deleted!")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")

        # Função para descriptografar arquivos pequenos
def decrypt_file(file_path, password_bytearray):
    try:
        sanitized_file_path = sanitize_filepath(file_path)
        if not os.path.exists(sanitized_file_path):
            messagebox.showerror("File Error", f"The file does not exist: {sanitized_file_path}")
            return

        # Lê o arquivo criptografado
        with open(sanitized_file_path, 'rb') as f:
            salt = f.read(32)  # Lê o salt
            iv = f.read(16)    # Lê o IV
            tag = f.read(16)   # Lê o tag
            hmac_value = f.read(32)  # Lê o HMAC
            encrypted_data = f.read()  # Lê os dados criptografados

        aes_key, hmac_key, _ = derive_key(password_bytearray, salt)
        secure_erase_memory(password_bytearray)

        # Verifica o HMAC
        hmac_input = salt + iv + tag + encrypted_data
        calculated_hmac = hmac.new(hmac_key, hmac_input, hashlib.sha256).digest()
        if hmac_value != calculated_hmac:
            messagebox.showerror("Error", "HMAC verification failed. The file may be corrupted or the wrong password was used.")
            return

        # Descriptografa os dados
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Grava o arquivo descriptografado
        decrypted_file_path = sanitized_file_path.replace('.aes', '')
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        secure_erase_memory(bytearray(encrypted_data))
        secure_erase_memory(bytearray(decrypted_data))

        messagebox.showinfo("Success", f"File decrypted successfully: {decrypted_file_path}")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {str(e)}")

# Função para deletar o arquivo de forma segura
def secure_delete(file_path):
    try:
        length = os.path.getsize(file_path)
        ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x80)
        ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x00)

        with open(file_path, 'r+b') as f:
            for _ in range(7):
                f.seek(0)
                f.write(secrets.token_bytes(length))

        os.remove(file_path)
        messagebox.showinfo("Success", f"File {file_path} securely deleted.")

    except FileNotFoundError:
        messagebox.showerror("Error", "File not found or already deleted.")
    except PermissionError:
        messagebox.showerror("Error", "Permission denied.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete file securely: {str(e)}")

# Função para determinar se um arquivo é grande e precisa de processamento em blocos
def is_large_file(file_path, size_threshold=500 * 1024 * 1024):
    return os.path.getsize(file_path) >= size_threshold

# Função para derivar chaves de criptografia
def derive_key(password_bytearray, salt=None):
    if salt is None:
        salt = secrets.token_bytes(32)

    password = bytes(password_bytearray)
    master_key = hash_secret_raw(
        password,
        salt,
        time_cost=6,
        memory_cost=2**17,
        parallelism=4,
        hash_len=64,
        type=Type.ID
    )

    aes_key = master_key[:32]
    hmac_key = master_key[32:]

    secure_erase_memory(password_bytearray)
    return aes_key, hmac_key, salt

# Função para executar a ação de criptografia ou descriptografia
def perform_action(action, password_entry, file_entry):
    password = password_entry.get()
    file_path = file_entry.get()

    if not password or not file_path:
        messagebox.showwarning("Input Error", "Please fill in all fields")
        return

    sanitized_file_path = sanitize_filepath(file_path)
    password_bytearray = bytearray(password, 'utf-8')

    try:
        if os.path.isdir(sanitized_file_path):
            if action == 'encrypt':
                encrypt_folder(sanitized_file_path, password_bytearray)
            else:
                messagebox.showerror("Action Error", "Batch decryption is not supported.")
        else:
            if is_large_file(sanitized_file_path):
                if action == 'encrypt':
                    encrypt_large_file(sanitized_file_path, password_bytearray)
                else:
                    messagebox.showerror("Action Error", "Large file decryption is not supported.")
            else:
                if action == 'encrypt':
                    encrypt_file(sanitized_file_path, password_bytearray)
                elif action == 'decrypt':
                    decrypt_file(sanitized_file_path, password_bytearray)
                else:
                    messagebox.showerror("Action Error", "Invalid action. Use 'encrypt' or 'decrypt'.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Função para aplicar o tema escuro
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

# Função para mostrar o teclado virtual
def show_virtual_keyboard():
    keyboard = tk.Toplevel(root)
    keyboard.title("Virtual Keyboard")
    keyboard.geometry("650x350")
    keyboard.resizable(False, False)
    
    # Matriz de teclas
    keyboard_buttons = [
        ('1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', 'Backspace'),
        ('q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\\'),
        ('a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', "'", 'Enter'),
        ('z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 'Shift'),
        ('´', '`', '{', '}', ':', '!', '@', '#', '$', '%', '&', '*', '()'),
        ('Space', 'Shift')
    ]
    
    shift_active = False

    # Função chamada ao pressionar uma tecla do teclado
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

    # Função para atualizar os botões do teclado, levando em consideração o estado do Shift
    def update_keyboard():
        for widget in keyboard.winfo_children():
            widget.destroy()
        
        for row_index, row in enumerate(keyboard_buttons):
            for col_index, key in enumerate(row):
                button_text = key
                if shift_active and key.isalpha():
                    button_text = key.upper()
                button = tk.Button(keyboard, text=button_text, width=5, height=2, font=('Helvetica', 12),
                                   command=lambda key=key: on_key_press(key))
                button.grid(row=row_index, column=col_index, padx=5, pady=5)
    
    update_keyboard()  # Inicializa o teclado

# Função para gerar senha de 45 caracteres
def generate_password():
    # Gera a senha
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(chars) for _ in range(45))
    
    # Limpa o campo de senha e insere a nova senha
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

# Função para alternar a visibilidade da senha
def toggle_password():
    if password_entry.cget("show") == "*":
        password_entry.config(show="")  # Mostra a senha (sem os asteriscos)
        toggle_button.config(text="Hide")  # Altera o texto do botão para 'Hide'
    else:
        password_entry.config(show="*")  # Esconde a senha (com asteriscos)
        toggle_button.config(text="Show")  # Altera o texto do botão para 'Show'

# Função para navegar e selecionar o arquivo
def browse_file():
    file_path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
    if file_path:  # Se um arquivo foi selecionado
        sanitized_file_path = sanitize_filepath(file_path)  # Sanitize path
        file_entry.configure(state='normal')  # Torna o campo editável temporariamente
        file_entry.delete(0, tk.END)  # Limpa o campo
        file_entry.insert(0, sanitized_file_path)  # Insere o caminho do arquivo selecionado
        file_entry.configure(state='disabled')  # Torna o campo desabilitado novamente


# GUI principal
root = tk.Tk()
root.title("AESCrypt Argon 6.2AK")  # Nome atualizado
root.geometry("655x350")
root.resizable(False, False)

set_dark_theme()  # Aplica o tema escuro

# Título principal
title_label = ttk.Label(root, text="AESCrypt Argon 6.2AK", font=('Helvetica', 16))
title_label.grid(row=0, column=0, columnspan=3, padx=10, pady=10)

# Instruções para o usuário
instructions_label = ttk.Label(
    root, text="Enter a password for encryption or decryption.",
    font=('Helvetica', 12),
    anchor='w', justify="left"
)
instructions_label.grid(row=1, column=0, columnspan=3, padx=10, pady=(0, 10))

# Label do arquivo
file_label = ttk.Label(root, text="File/Folder:")
file_label.grid(row=2, column=0, padx=10, pady=5, sticky='e')

# Campo de entrada para o arquivo
file_entry = ttk.Entry(root, width=60, state='readonly')  # Usando readonly para não permitir digitação
file_entry.grid(row=2, column=1, padx=10, pady=5)

# Botão "Browse" para abrir o navegador de arquivos
browse_button = ttk.Button(root, text="Browse", command=browse_file)
browse_button.grid(row=2, column=2, padx=10, pady=5)

# Campo de senha
password_label = ttk.Label(root, text="Password:")  # Label do campo de senha
password_label.grid(row=3, column=0, padx=10, pady=5, sticky='e')

generate_button = ttk.Button(root, text="Generate Password", command=generate_password)
generate_button.grid(row=5, column=2, padx=10, pady=5)

password_entry = ttk.Entry(root, show="*", width=40, font=('Helvetica', 12))
password_entry.grid(row=3, column=1, padx=10, pady=5)

toggle_button = ttk.Button(root, text="Show", command=toggle_password)
toggle_button.grid(row=3, column=2, padx=10, pady=5)

# Botão para mostrar o teclado virtual
keyboard_button = ttk.Button(root, text="Show Keyboard", command=show_virtual_keyboard)
keyboard_button.grid(row=4, column=2, padx=10, pady=5)

# Botões de "Encrypt" e "Decrypt"
encrypt_button = ttk.Button(
    root, text="Encrypt", style="EncryptButton.TButton", command=lambda: perform_action("encrypt", password_entry, file_entry)
)
encrypt_button.grid(row=4, column=0, padx=10, pady=20)

decrypt_button = ttk.Button(
    root, text="Decrypt", style="DecryptButton.TButton", command=lambda: perform_action("decrypt", password_entry, file_entry)
)
decrypt_button.grid(row=4, column=1, padx=10, pady=20)

root.mainloop()
