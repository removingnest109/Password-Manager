import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import tkinter as tk
import pyperclip
import tkinter.messagebox as messagebox
import os
import configparser
import hashlib
import base64

config_file = 'config.ini'
config = configparser.ConfigParser()
def login():
    root = tk.Tk()
    root.title("Login")
    lbl_password = tk.Label(root, text="Please enter password:")
    lbl_password.pack(side=tk.TOP)
    password_entry = tk.Entry(root, show="*")
    password_entry.pack(side=tk.TOP)
    def check_password():
        user_input = password_entry.get()
        hashed_input = hashlib.sha256(user_input.encode()).hexdigest()
        if config.get('keys', 'user_password').strip() == hashed_input.strip():
            root.destroy()
            main()
        else:
            password_entry.delete(0, tk.END)
            lbl_password.config(text="Incorrect password, please try again.")
    btn_login = tk.Button(root, text="Login", command=check_password)
    btn_login.pack(side=tk.TOP)
    root.mainloop()
def main():
    iterations = 100000  # Number of iterations (higher is more secure but slower)
    key_length = 32  # Length of the derived key in bytes
    config.read(config_file)
    user_password = config.get('keys', 'user_password')
    salt = user_password.encode('utf-8')
    key_32 = hashlib.pbkdf2_hmac('sha256', user_password.encode('utf-8'), salt, iterations, key_length)
    def encrypt(password, key):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(password.encode('utf-8'))
        return base64.b64encode(iv + ciphertext)
    def decrypt(ciphertext, key):
        ciphertext = base64.urlsafe_b64decode(ciphertext)
        # remove padding if necessary
        padding_pos = ciphertext.find(b'=')
        if padding_pos != -1:
            ciphertext = ciphertext[:padding_pos]
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:]).decode('utf-8')
        return plaintext
    def create_password_database():
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL)''')
        conn.commit()
        conn.close()
    def add_password(service, username, password, key):
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        encrypted_password = encrypt(password, key)
        c.execute('''REPLACE INTO passwords (service, username, password)
                    VALUES (?, ?, ?)''', (service, username, encrypted_password))
        conn.commit()
        conn.close()
    def get_password(service, key):
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute("SELECT * FROM passwords WHERE service=?", (service,))
        result = c.fetchone()
        conn.close()
        if result:
            encrypted_password = result[3]
            password = decrypt(encrypted_password, key)
            return result[2], password
        else:
            return None
    def show_password(key):
        service = lb_services.get(lb_services.curselection())
        username, password = get_password(service, key)
        lbl_service.config(text=f"Service: {service}")
        lbl_username.config(text=f"Username: {username}")
        lbl_password.config(text=f"Password: {password}")
    create_password_database()
    def add_credential():
        key = key_32
        # Create new window for adding credentials
        add_credential_window = tk.Toplevel(root)
        add_credential_window.title("Add Credential")
        # Labels and entries for service, username, and password
        service_label = tk.Label(add_credential_window, text="Service:")
        service_label.grid(row=0, column=0, padx=5, pady=5)
        service_entry = tk.Entry(add_credential_window)
        service_entry.grid(row=0, column=1, padx=5, pady=5)
        username_label = tk.Label(add_credential_window, text="Username:")
        username_label.grid(row=1, column=0, padx=5, pady=5)
        username_entry = tk.Entry(add_credential_window)
        username_entry.grid(row=1, column=1, padx=5, pady=5)
        password_label = tk.Label(add_credential_window, text="Password:")
        password_label.grid(row=2, column=0, padx=5, pady=5)
        password_entry = tk.Entry(add_credential_window, show="*")
        password_entry.grid(row=2, column=1, padx=5, pady=5)
        # Add button to submit credentials
        add_button = tk.Button(add_credential_window, text="Add",
                                command=lambda: add_credential_submit(
                                    service_entry.get(), username_entry.get(),
                                    password_entry.get()))
        add_button.grid(row=3, column=1, padx=5, pady=5)
        # Function to submit credentials and add to database
        def add_credential_submit(service, username, password):
            add_password(service, username, password, key)
            messagebox.showinfo("Success", "Credential added!")
            add_credential_window.destroy()
            refresh_services()
    # Create GUI
    root = tk.Tk()
    root.title("Password Manager")
    lbl_password = tk.Label(root, text="")
    lbl_password.pack(side=tk.RIGHT)
    lbl_service = tk.Label(root, text="")
    lbl_service.pack(side=tk.RIGHT)
    lbl_username = tk.Label(root, text="")
    lbl_username.pack(side=tk.RIGHT)
    def delete_credential():
        selected_service = lb_services.get(lb_services.curselection())
        confirm = messagebox.askyesno("Confirm deletion", f"Are you sure you want to delete the {selected_service} credential?")
        if confirm:
            conn = sqlite3.connect('passwords.db')
            c = conn.cursor()
            c.execute("DELETE FROM passwords WHERE service=?", (selected_service,))
            conn.commit()
            conn.close()
            refresh_services()
            lbl_service.config(text="")
            lbl_username.config(text="")
            lbl_password.config(text="")
    def refresh_services():
    # Clear current list of services
        lb_services.delete(0, tk.END)
        # Query database for list of services
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()
        c.execute("SELECT service FROM passwords")
        result = c.fetchall()
        conn.close()
        # Update listbox with new list of services
        for service in result:
            lb_services.insert(tk.END, service[0])
    def copy_password():
        selected_password = lbl_password['text']
        password = selected_password.split(": ")[-1] 
        pyperclip.copy(password)
        lbl_copy_confirm = tk.Label(root, text="Password copied to clipboard!")
        lbl_copy_confirm.pack()
    btn_copy_password = tk.Button(root, text="Copy Password", command=copy_password)
    btn_copy_password.pack()
    # Service Listbox
    lb_services = tk.Listbox(root)
    lb_services.pack(side=tk.LEFT)
    # Button to add credential
    add_credential_button = tk.Button(root, text="Add Credential", command=add_credential)
    add_credential_button.pack(side=tk.TOP, padx=5, pady=5)
    btn_delete = tk.Button(root, text="Delete Credential", command=delete_credential)
    btn_delete.pack(side=tk.TOP, padx=5, pady=5)
    # Load services into listbox
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT service FROM passwords")
    result = c.fetchall()
    conn.close()
    for service in result:
        lb_services.insert(tk.END, service[0])
    lb_services.bind('<<ListboxSelect>>', lambda event: show_password(key_32))
    root.mainloop()
if not os.path.isfile(config_file):
    # prompt user to set password
    root = tk.Tk()
    root.title("Set Password")
    lbl_password = tk.Label(root, text="Please set a password:")
    lbl_password.pack(side=tk.TOP)
    password_entry = tk.Entry(root, show="*")
    password_entry.pack(side=tk.TOP)
    def set_password():
        password = password_entry.get()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        config['keys'] = {'user_password': hashed_password}
        with open(config_file, 'w') as f:
            config.write(f)
        root.destroy()
    btn_set_password = tk.Button(root, text="Set Password", command=set_password)
    btn_set_password.pack(side=tk.TOP)
    root.mainloop()
else:
    config.read(config_file)
    login()
