import os
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import json
import base64

# --- Security Warning ---
# This is a simplified example for educational purposes.
# It is NOT production-ready and has potential security vulnerabilities.
# DO NOT use this code to store your actual sensitive data.
# --- Security Warning ---

FILENAME = "passwords.dat"

def generate_key(master_password: str, salt: bytes = None) -> bytes:
    """Generates an encryption key from the master password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,  # Increase for more security
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key, salt

def encrypt_data(data: dict, key: bytes) -> bytes:
    """Encrypts the given data using Fernet."""
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())
    return encrypted_data

def decrypt_data(encrypted_data: bytes, key: bytes) -> dict:
    """Decrypts the given data using Fernet."""
    f = Fernet(key)
    decrypted_data = json.loads(f.decrypt(encrypted_data).decode())
    return decrypted_data

def load_data(master_password):
    """Loads and decrypts data, or returns an empty list if the file doesn't exist or password is wrong."""
    try:
        with open(FILENAME, "rb") as f:
            salt_b64 = f.readline().strip()
            encrypted_data = f.read()
        salt = base64.b64decode(salt_b64)
        key, _ = generate_key(master_password, salt)
        return decrypt_data(encrypted_data, key)
    except FileNotFoundError:
        return []
    except:
        messagebox.showerror("Error", "Incorrect master password!")
        return None

def save_data(data, master_password, salt):
    """Encrypts and saves the data."""
    key, _ = generate_key(master_password, salt)
    encrypted_data = encrypt_data(data, key)
    with open(FILENAME, "wb") as f:
        f.write(base64.b64encode(salt) + b'\n')
        f.write(encrypted_data)

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        master.title("Simple Password Manager")

        self.master_password = self.ask_master_password()
        if self.master_password is None:
            self.master.destroy()
            return

        self.data = load_data(self.master_password)
        if self.data is None:
            self.data = []

        self.salt = self.load_salt()

        self.tree = ttk.Treeview(master, columns=("Service", "Username", "Password"))
        self.tree.heading("#1", text="Service")
        self.tree.heading("#2", text="Username")
        self.tree.heading("#3", text="Password")
        self.tree.pack(pady=10, expand=True, fill='both')
        self.populate_tree()
        self.tree.bind("<Double-1>", self.show_details)

        add_button = tk.Button(master, text="Add New", command=self.add_new_entry)
        add_button.pack(pady=5)

        delete_button = tk.Button(master, text="Delete Selected", command=self.delete_entry)
        delete_button.pack(pady=5)

        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def ask_master_password(self):
        password_window = tk.Toplevel(self.master)
        password_window.title("Enter your computer Password")
        password_window.resizable(False, False)

        password_label = tk.Label(password_window, text="Enter your computer Password:")
        password_label.pack(padx=10, pady=5)

        password_entry = tk.Entry(password_window, show="*")
        password_entry.pack(padx=10, pady=5)
        password_entry.focus_set()

        def submit_password():
            self.temp_password = password_entry.get()
            password_window.destroy()

        submit_button = tk.Button(password_window, text="Submit", command=submit_password)
        submit_button.pack(pady=10)

        password_window.wait_window()
        return getattr(self, 'temp_password', None)

    def load_salt(self):
        try:
            with open(FILENAME, "rb") as f:
                salt_b64 = f.readline().strip()
            return base64.b64decode(salt_b64)
        except FileNotFoundError:
            return os.urandom(16)
        except:
            return os.urandom(16) # Handle potential errors reading salt

    def populate_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for entry in self.data:
            self.tree.insert("", tk.END, values=(entry["service"], entry["username"], "*" * len(entry["password"])))

    def add_new_entry(self):
        add_window = tk.Toplevel(self.master)
        add_window.title("Add New Entry")

        service_label = tk.Label(add_window, text="Service:")
        service_label.grid(row=0, column=0, padx=5, pady=5, sticky='w')
        service_entry = tk.Entry(add_window)
        service_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        username_label = tk.Label(add_window, text="Username/Card/email:")
        username_label.grid(row=1, column=0, padx=5, pady=5, sticky='w')
        username_entry = tk.Entry(add_window)
        username_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        password_label = tk.Label(add_window, text="Password/Details:")
        password_label.grid(row=2, column=0, padx=5, pady=5, sticky='w')
        password_entry = tk.Entry(add_window, show="*")
        password_entry.grid(row=2, column=1, padx=5, pady=5, sticky='ew')

        def save_new_entry():
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            if service and username and password:
                self.data.append({"service": service, "username": username, "password": password})
                self.populate_tree()
                add_window.destroy()
            else:
                messagebox.showerror("Error", "All fields are required.")

        save_button = tk.Button(add_window, text="Save", command=save_new_entry)
        save_button.grid(row=3, column=0, columnspan=2, pady=10)
        add_window.grid_columnconfigure(1, weight=1)

    def show_details(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            index = self.tree.index(selected_item[0])
            entry = self.data[index]
            messagebox.showinfo(
                "Details",
                f"Service: {entry['service']}\nUsername/Card/Email: {entry['username']}\nPassword/Details: {entry['password']}"
            )

    def delete_entry(self):
        selected_item = self.tree.selection()
        if selected_item:
            if messagebox.askyesno("Confirm", "Are you sure you want to delete the selected entry?"):
                index = self.tree.index(selected_item[0])
                del self.data[index]
                self.populate_tree()

    def on_closing(self):
        if self.master_password is not None:
            save_data(self.data, self.master_password, self.salt)
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
