import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import secrets
import hmac
import string
import threading
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2.low_level import hash_secret_raw
from argon2 import Type
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

# Função para sanitizar o caminho do arquivo
def sanitize_filepath(file_path):
    return os.path.normpath(file_path)

# Função para apagar dados de memória de forma segura usando PyNaCl
def secure_erase_memory(data):
    if isinstance(data, (bytearray, memoryview)):
        random_data = nacl_random(len(data))
        for i in range(len(data)):
            data[i] = random_data[i]
        del random_data
    else:
        raise TypeError("Data must be a mutable object like bytearray or memoryview.")

# Função para deletar arquivo de forma segura usando padrões avançados
def secure_delete(file_path):
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError("File not found.")

        length = os.path.getsize(file_path)
        with open(file_path, 'r+b') as f:
            for _ in range(3):
                f.seek(0)
                f.write(b'\x00' * length)  # Preenche com zeros
                os.fsync(f.fileno())  # Força a escrita no disco
                f.seek(0)
                f.write(b'\xFF' * length)  # Preenche com 1s
                os.fsync(f.fileno())  # Força a escrita no disco
                f.seek(0)
                f.write(nacl_random(length))  # Preenche com dados aleatórios
                os.fsync(f.fileno())  # Força a escrita no disco
        os.remove(file_path)
    except Exception as e:
        raise IOError(f"Failed to securely delete file: {e}")

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


# Função para verificar integridade usando HMAC
def verify_hmac(hmac_key, hmac_input, expected_hmac):
    calculated_hmac = hmac.new(hmac_key, hmac_input, hashlib.sha256).digest()
    if not hmac.compare_digest(calculated_hmac, expected_hmac):
        raise ValueError("HMAC check failed. The file might be tampered with.")

# Função para verificar se o arquivo é grande
def is_large_file(file_path, size_threshold=500 * 1024 * 1024):
    return os.path.getsize(file_path) >= size_threshold

# Função para dividir dados em blocos
def split_data(data, block_size):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

# Função para gerar padding aleatório
def generate_random_padding(size):
    return secrets.token_bytes(size)

# Função para criptografar arquivos com multithreading
def encrypt_file(file_path, password_bytearray):
    try:
        sanitized_file_path = sanitize_filepath(file_path)
        if not os.path.exists(sanitized_file_path):
            raise FileNotFoundError(f"The file does not exist: {sanitized_file_path}")

        # Lê o arquivo original em blocos para evitar sobrecarga de memória
        file_data = bytearray()
        with open(sanitized_file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                file_data.extend(byte_block)

        salt = secrets.token_bytes(32)
        password_memory = memoryview(password_bytearray)  # Uso de memoryview para maior segurança
        aes_key, hmac_key, _ = derive_key(password_memory, salt)
        secure_erase_memory(password_memory)

        # Gera padding aleatório para disfarçar o tamanho do arquivo
        random_padding = generate_random_padding(1048576)  # 1MB de padding aleatório
        padded_data = file_data + random_padding

        # Ajusta o tamanho para múltiplos de 16 bytes
        padded_data += b'\x00' * (16 - len(padded_data) % 16)

        data_blocks = split_data(padded_data, 1048576)  # 1MB por bloco

        encrypted_data = []
        ivs = []  # Armazenar IVs por bloco
        tags = []  # Armazenar tags por bloco

        used_ivs = set()  # Garante IVs únicos

        def encrypt_block(block):
            while True:
                iv = secrets.token_bytes(16)
                if iv not in used_ivs:
                    used_ivs.add(iv)
                    break
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            encrypted_block = encryptor.update(block) + encryptor.finalize()
            return encrypted_block, encryptor.tag, iv

        threads = []
        results = [None] * len(data_blocks)

        def thread_worker(index, block):
            results[index] = encrypt_block(block)

        for i, block in enumerate(data_blocks):
            thread = threading.Thread(target=thread_worker, args=(i, block))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        for result in results:
            encrypted_data.append(result[0])
            tags.append(result[1])
            ivs.append(result[2])

        encrypted_data = b"".join(encrypted_data)

        hmac_input = salt + b"".join(ivs) + b"".join(tags) + encrypted_data
        hmac_value = hmac.new(hmac_key, hmac_input, hashlib.sha256).digest()

        encrypted_file_path = f"{sanitized_file_path}.aes"
        with open(encrypted_file_path, 'wb') as f:
            f.write(salt)
            f.write(len(data_blocks).to_bytes(4, 'big'))  # Escreve o número de blocos
            for iv in ivs:
                f.write(iv)
            for tag in tags:
                f.write(tag)
            f.write(hmac_value)
            f.write(encrypted_data)
            f.write(len(random_padding).to_bytes(4, 'big'))  # Armazena o tamanho do padding

        secure_erase_memory(file_data)
        secure_erase_memory(bytearray(padded_data))
        secure_erase_memory(bytearray(encrypted_data))

        secure_delete(sanitized_file_path)

        messagebox.showinfo("Success", f"File encrypted and original file securely deleted.")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during encryption: {e}")


# Função para descriptografar arquivos com multithreading
def decrypt_file(file_path, password_bytearray):
    try:
        sanitized_file_path = sanitize_filepath(file_path)
        if not os.path.exists(sanitized_file_path):
            raise FileNotFoundError(f"The file does not exist: {sanitized_file_path}")

        with open(sanitized_file_path, 'rb') as f:
            salt = f.read(32)
            num_blocks = int.from_bytes(f.read(4), 'big')  # Lê o número de blocos
            ivs = [f.read(16) for _ in range(num_blocks)]
            tags = [f.read(16) for _ in range(num_blocks)]
            hmac_value = f.read(32)
            encrypted_data = f.read()

        padding_size = int.from_bytes(encrypted_data[-4:], 'big')  # Lê o tamanho do padding
        encrypted_data = encrypted_data[:-4]  # Remove o tamanho do padding

        password_memory = memoryview(password_bytearray)  # Uso de memoryview para maior segurança
        aes_key, hmac_key, _ = derive_key(password_memory, salt)
        secure_erase_memory(password_memory)

        hmac_input = salt + b"".join(ivs) + b"".join(tags) + encrypted_data
        verify_hmac(hmac_key, hmac_input, hmac_value)

        data_blocks = split_data(encrypted_data, 1048576)  # 1MB por bloco

        decrypted_data = []

        def decrypt_block(block, iv, tag):
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            return decryptor.update(block) + decryptor.finalize()

        threads = []
        results = [None] * len(data_blocks)

        def thread_worker(index, block):
            try:
                results[index] = decrypt_block(block, ivs[index], tags[index])
            except Exception as e:
                results[index] = None  # Marcar como inválido

        for i, block in enumerate(data_blocks):
            thread = threading.Thread(target=thread_worker, args=(i, block))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Validar e filtrar resultados
        decrypted_data = b"".join(filter(None, results))
        if not decrypted_data:
            raise ValueError("Decryption failed. No valid data blocks found.")

        # Remove o padding aleatório antes de salvar
        decrypted_data = decrypted_data[:-(padding_size)]

        decrypted_file_path = sanitized_file_path.replace(".aes", "")
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data.rstrip(b'\x00'))

        secure_erase_memory(bytearray(encrypted_data))
        secure_erase_memory(bytearray(decrypted_data))

        messagebox.showinfo("Success", f"File decrypted successfully: {decrypted_file_path}")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {e}")

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
root.title("AESCrypt Argon 2025AK")  # Nome atualizado
root.geometry("655x350")
root.resizable(False, False)

set_dark_theme()  # Aplica o tema escuro

# Título principal
title_label = ttk.Label(root, text="AESCrypt Argon 2025AK", font=('Helvetica', 16))
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
