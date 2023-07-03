import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.backends import default_backend

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_key_text.delete("1.0", tk.END)
    private_key_text.insert(tk.END, private_key_pem.decode())

    public_key_text.delete("1.0", tk.END)
    public_key_text.insert(tk.END, public_key_pem.decode())

def encrypt_message():
    message = message_text.get("1.0", tk.END).strip()
    public_key = public_key_text.get("1.0", tk.END).strip()

    if not message:
        messagebox.showerror("Fehler", "Bitte geben Sie eine Nachricht ein.")
        return

    if not public_key:
        messagebox.showerror("Fehler", "Bitte geben Sie einen öffentlichen Schlüssel ein.")
        return

    try:
        public_key = serialization.load_pem_public_key(public_key.encode(), backend=default_backend())
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding=OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_text.delete("1.0", tk.END)
        encrypted_text.insert(tk.END, encrypted_message.hex())
    except:
        messagebox.showerror("Fehler", "Verschlüsselung fehlgeschlagen.")

def decrypt_message():
    encrypted_message = encrypted_text.get("1.0", tk.END).strip()
    private_key = private_key_text.get("1.0", tk.END).strip()

    if not encrypted_message:
        messagebox.showerror("Fehler", "Bitte geben Sie eine verschlüsselte Nachricht ein.")
        return

    if not private_key:
        messagebox.showerror("Fehler", "Bitte geben Sie einen privaten Schlüssel ein.")
        return

    try:
        private_key = serialization.load_pem_private_key(private_key.encode(), password=None, backend=default_backend())
        decrypted_message = private_key.decrypt(
            bytes.fromhex(encrypted_message),
            padding=OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_text.delete("1.0", tk.END)
        decrypted_text.insert(tk.END, decrypted_message.decode())
    except:
        messagebox.showerror("Fehler", "Entschlüsselung fehlgeschlagen.")

def save_private_key():
    private_key_pem = private_key_text.get("1.0", tk.END).strip()
    filepath = filedialog.asksaveasfilename(defaultextension=".asc", filetypes=(("ASC Files", "*.asc"), ("All Files", "*.*")))
    if filepath and private_key_pem:
        with open(filepath, "wb") as file:
            file.write(private_key_pem.encode())

def save_public_key():
    public_key_pem = public_key_text.get("1.0", tk.END).strip()
    filepath = filedialog.asksaveasfilename(defaultextension=".asc", filetypes=(("ASC Files", "*.asc"), ("All Files", "*.*")))
    if filepath and public_key_pem:
        with open(filepath, "wb") as file:
            file.write(public_key_pem.encode())

root = tk.Tk()
root.title("PGP Tool by Maik Jeschke")
root.geometry("800x600")

# Funktionen für das Menü

def quit_program():
    root.quit()


# Menü

menubar = tk.Menu(root)

file_menu = tk.Menu(menubar, tearoff=0)
file_menu.add_command(label="Private Key speichern", command=save_private_key)
file_menu.add_command(label="Public Key speichern", command=save_public_key)
file_menu.add_separator()
file_menu.add_command(label="Beenden", command=quit_program)


menubar.add_cascade(label="Datei", menu=file_menu)

root.config(menu=menubar)

# GUI-Elemente

generate_keypair_button = tk.Button(root, text="Schlüsselpaar generieren", command=generate_key_pair)
generate_keypair_button.pack(pady=10)

message_label = tk.Label(root, text="Nachricht:")
message_label.pack()
message_text = tk.Text(root, width=40, height=5)
message_text.pack()

public_key_label = tk.Label(root, text="Öffentlicher Schlüssel:")
public_key_label.pack()
public_key_text = tk.Text(root, width=40, height=5)
public_key_text.pack()

private_key_label = tk.Label(root, text="Privater Schlüssel:")
private_key_label.pack()
private_key_text = tk.Text(root, width=40, height=5)
private_key_text.pack()

encrypt_button = tk.Button(root, text="Nachricht verschlüsseln", command=encrypt_message)
encrypt_button.pack(side=tk.LEFT, padx=10)

decrypt_button = tk.Button(root, text="Nachricht entschlüsseln", command=decrypt_message)
decrypt_button.pack(side=tk.LEFT, padx=10)

encrypted_label = tk.Label(root, text="Verschlüsselte Nachricht:")
encrypted_label.pack()
encrypted_text = tk.Text(root, width=40, height=5)
encrypted_text.pack()

decrypted_label = tk.Label(root, text="Entschlüsselte Nachricht:")
decrypted_label.pack()
decrypted_text = tk.Text(root, width=40, height=5)
decrypted_text.pack()

root.mainloop()
