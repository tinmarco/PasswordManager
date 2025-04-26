import os
import base64
import json
import secrets
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import pyperclip  # For clipboard functionality
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        # Set application icon (optional)
        # self.root.iconbitmap('icon.ico')  # Create and add your own icon
        
        # Password manager backend
        self.password_manager = PasswordManager()
        
        # Variables
        self.is_logged_in = False
        
        # Create the login frame
        self.create_login_frame()
    
    def create_login_frame(self):
        """Create the login screen"""
        self.login_frame = ttk.Frame(self.root, padding="20")
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(self.login_frame, text="Secure Password Manager", 
                 font=("Helvetica", 16)).pack(pady=20)
        
        # Master password entry
        ttk.Label(self.login_frame, text="Enter Master Password:").pack(pady=5)
        self.master_password_var = tk.StringVar()
        self.master_password_entry = ttk.Entry(self.login_frame, 
                                              textvariable=self.master_password_var, 
                                              show="•")
        self.master_password_entry.pack(pady=5, ipadx=50)
        self.master_password_entry.focus()
        
        # Buttons frame
        button_frame = ttk.Frame(self.login_frame)
        button_frame.pack(pady=20)
        
        # Login button
        ttk.Button(button_frame, text="Login", 
                  command=self.login).pack(side=tk.LEFT, padx=5)
        
        # Create new button
        ttk.Button(button_frame, text="Create New", 
                  command=self.create_new).pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda event: self.login())
    
    def login(self):
        """Attempt to login with the provided master password"""
        master_password = self.master_password_var.get()
        
        if not master_password:
            messagebox.showerror("Error", "Please enter a master password")
            return
        
        if self.password_manager.load(master_password):
            self.is_logged_in = True
            self.login_frame.destroy()
            self.create_main_app()
        else:
            messagebox.showerror("Error", "Invalid master password or no password file found")
    
    def create_new(self):
        """Create a new password database"""
        master_password = self.master_password_var.get()
        
        if not master_password:
            messagebox.showerror("Error", "Please enter a master password")
            return
        
        # Confirm password
        confirm = simpledialog.askstring("Confirm Password", 
                                        "Confirm your master password:", 
                                        show="•")
        
        if confirm != master_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        self.password_manager.generate_master_key(master_password)
        messagebox.showinfo("Success", "New password database created")
        
        self.is_logged_in = True
        self.login_frame.destroy()
        self.create_main_app()
    
    def create_main_app(self):
        """Create the main application interface"""
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create top frame for actions
        top_frame = ttk.Frame(self.main_frame)
        top_frame.pack(fill=tk.X, pady=10)
        
        # Add password button
        ttk.Button(top_frame, text="Add Password", 
                  command=self.show_add_password).pack(side=tk.LEFT, padx=5)
        
        # Generate password button
        ttk.Button(top_frame, text="Generate Password", 
                  command=self.show_generate_password).pack(side=tk.LEFT, padx=5)
        
        # Search field
        ttk.Label(top_frame, text="Search:").pack(side=tk.LEFT, padx=(20, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda name, index, mode: self.filter_passwords())
        ttk.Entry(top_frame, textvariable=self.search_var).pack(side=tk.LEFT, 
                                                              fill=tk.X, 
                                                              expand=True, 
                                                              padx=5)
        
        # Create password list
        list_frame = ttk.LabelFrame(self.main_frame, text="Saved Passwords")
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Treeview for passwords
        self.password_tree = ttk.Treeview(list_frame, columns=("Service", "Username"), 
                                         show="headings")
        self.password_tree.heading("Service", text="Service")
        self.password_tree.heading("Username", text="Username")
        self.password_tree.column("Service", width=150)
        self.password_tree.column("Username", width=150)
        self.password_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, 
                                 command=self.password_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.password_tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind double-click to view password
        self.password_tree.bind("<Double-1>", self.show_password_details)
        
        # Right-click menu
        self.context_menu = tk.Menu(self.password_tree, tearoff=0)
        self.context_menu.add_command(label="Copy Username", 
                                     command=lambda: self.copy_field("username"))
        self.context_menu.add_command(label="Copy Password", 
                                     command=lambda: self.copy_field("password"))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Edit", command=self.edit_selected)
        self.context_menu.add_command(label="Delete", command=self.delete_selected)
        
        self.password_tree.bind("<Button-3>", self.show_context_menu)
        
        # Status bar
        self.status_var = tk.StringVar()
        ttk.Label(self.main_frame, textvariable=self.status_var, 
                 relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.BOTTOM, 
                                                    fill=tk.X)
        
        # Save on close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Load passwords
        self.load_passwords()
    
    def load_passwords(self):
        """Load passwords into the treeview"""
        # Clear existing items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        # Add passwords to tree
        for service, details in self.password_manager.passwords.items():
            self.password_tree.insert("", tk.END, values=(service, details["username"]))
        
        self.status_var.set(f"Loaded {len(self.password_manager.passwords)} passwords")
    
    def filter_passwords(self):
        """Filter passwords based on search query"""
        query = self.search_var.get().lower()
        
        # Clear existing items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        # Add matching passwords
        for service, details in self.password_manager.passwords.items():
            if (query in service.lower() or 
                query in details["username"].lower()):
                self.password_tree.insert("", tk.END, values=(service, details["username"]))
    
    def show_add_password(self):
        """Show dialog to add a new password"""
        add_window = tk.Toplevel(self.root)
        add_window.title("Add Password")
        add_window.geometry("400x250")
        add_window.resizable(False, False)
        add_window.transient(self.root)
        add_window.grab_set()
        
        ttk.Label(add_window, text="Add New Password", 
                 font=("Helvetica", 12)).grid(row=0, column=0, 
                                             columnspan=2, 
                                             pady=10, padx=10)
        
        # Service
        ttk.Label(add_window, text="Service:").grid(row=1, column=0, 
                                                   sticky=tk.W, pady=5, padx=10)
        service_var = tk.StringVar()
        ttk.Entry(add_window, textvariable=service_var, width=30).grid(row=1, column=1, 
                                                                      pady=5, padx=10)
        
        # Username
        ttk.Label(add_window, text="Username:").grid(row=2, column=0, 
                                                    sticky=tk.W, pady=5, padx=10)
        username_var = tk.StringVar()
        ttk.Entry(add_window, textvariable=username_var, width=30).grid(row=2, column=1, 
                                                                       pady=5, padx=10)
        
        # Password
        ttk.Label(add_window, text="Password:").grid(row=3, column=0, 
                                                    sticky=tk.W, pady=5, padx=10)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(add_window, textvariable=password_var, 
                                  width=30, show="•")
        password_entry.grid(row=3, column=1, pady=5, padx=10)
        
        # Password visibility toggle
        show_password_var = tk.BooleanVar()
        ttk.Checkbutton(add_window, text="Show Password", 
                       variable=show_password_var, 
                       command=lambda: password_entry.config(
                           show="" if show_password_var.get() else "•"
                       )).grid(row=4, column=1, sticky=tk.W, pady=5, padx=10)
        
        # Generate button
        ttk.Button(add_window, text="Generate", 
                  command=lambda: password_var.set(
                      self.password_manager.generate_password()
                  )).grid(row=4, column=0, sticky=tk.W, pady=5, padx=10)
        
        # Buttons
        button_frame = ttk.Frame(add_window)
        button_frame.grid(row=5, column=0, columnspan=2, pady=15)
        
        ttk.Button(button_frame, text="Save", 
                  command=lambda: self.add_password(
                      add_window, 
                      service_var.get(), 
                      username_var.get(), 
                      password_var.get()
                  )).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Cancel", 
                  command=add_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def add_password(self, window, service, username, password):
        """Add a new password entry"""
        if not service or not username or not password:
            messagebox.showerror("Error", "All fields are required", parent=window)
            return
        
        self.password_manager.add_password(service, username, password)
        self.password_manager.save()
        window.destroy()
        self.load_passwords()
        
        self.status_var.set(f"Added password for {service}")
    
    def show_generate_password(self):
        """Show dialog to generate a password"""
        gen_window = tk.Toplevel(self.root)
        gen_window.title("Generate Password")
        gen_window.geometry("400x280")
        gen_window.resizable(False, False)
        gen_window.transient(self.root)
        gen_window.grab_set()
        
        ttk.Label(gen_window, text="Generate Strong Password", 
                 font=("Helvetica", 12)).grid(row=0, column=0, 
                                             columnspan=2, 
                                             pady=10, padx=10)
        
        # Length
        ttk.Label(gen_window, text="Length:").grid(row=1, column=0, 
                                                  sticky=tk.W, pady=5, padx=10)
        length_var = tk.IntVar(value=16)
        ttk.Spinbox(gen_window, from_=8, to=64, 
                   textvariable=length_var, width=5).grid(row=1, column=1, 
                                                         sticky=tk.W, pady=5, padx=10)
        
        # Character sets
        ttk.Label(gen_window, text="Include:").grid(row=2, column=0, 
                                                   sticky=tk.W, pady=5, padx=10)
        options_frame = ttk.Frame(gen_window)
        options_frame.grid(row=2, column=1, sticky=tk.W, pady=5, padx=10)
        
        uppercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Uppercase (A-Z)", 
                       variable=uppercase_var).pack(anchor=tk.W)
        
        lowercase_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Lowercase (a-z)", 
                       variable=lowercase_var).pack(anchor=tk.W)
        
        digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Digits (0-9)", 
                       variable=digits_var).pack(anchor=tk.W)
        
        symbols_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Symbols (!@#$%^&*)", 
                       variable=symbols_var).pack(anchor=tk.W)
        
        # Generated password
        ttk.Label(gen_window, text="Password:").grid(row=3, column=0, 
                                                    sticky=tk.W, pady=5, padx=10)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(gen_window, textvariable=password_var, 
                                  width=30, state="readonly")
        password_entry.grid(row=3, column=1, sticky=tk.W, pady=5, padx=10)
        
        # Buttons
        button_frame = ttk.Frame(gen_window)
        button_frame.grid(row=4, column=0, columnspan=2, pady=15)
        
        def generate():
            """Generate password with selected options"""
            charset = ""
            if uppercase_var.get():
                charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            if lowercase_var.get():
                charset += "abcdefghijklmnopqrstuvwxyz"
            if digits_var.get():
                charset += "0123456789"
            if symbols_var.get():
                charset += "!@#$%^&*()-_=+[]{}|;:,.<>?/"
            
            if not charset:
                messagebox.showerror("Error", "Select at least one character set", 
                                    parent=gen_window)
                return
            
            password = ''.join(secrets.choice(charset) for _ in range(length_var.get()))
            password_var.set(password)
        
        ttk.Button(button_frame, text="Generate", 
                  command=generate).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Copy", 
                  command=lambda: [pyperclip.copy(password_var.get()),
                                   self.status_var.set("Password copied to clipboard")]).\
                  pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Close", 
                  command=gen_window.destroy).pack(side=tk.LEFT, padx=5)
        
        # Generate initial password
        generate()
    
    def show_password_details(self, event):
        """Show details for the selected password"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        service = self.password_tree.item(item, "values")[0]
        entry = self.password_manager.get_password(service)
        
        if entry:
            details_window = tk.Toplevel(self.root)
            details_window.title(f"Password Details - {service}")
            details_window.geometry("400x200")
            details_window.resizable(False, False)
            details_window.transient(self.root)
            details_window.grab_set()
            
            ttk.Label(details_window, text=f"Details for {service}", 
                     font=("Helvetica", 12)).pack(pady=10)
            
            details_frame = ttk.Frame(details_window, padding="10")
            details_frame.pack(fill=tk.BOTH, expand=True)
            
            # Username
            ttk.Label(details_frame, text="Username:").grid(row=0, column=0, 
                                                          sticky=tk.W, pady=5)
            username_var = tk.StringVar(value=entry["username"])
            username_entry = ttk.Entry(details_frame, textvariable=username_var, 
                                      width=30, state="readonly")
            username_entry.grid(row=0, column=1, sticky=tk.W, pady=5)
            ttk.Button(details_frame, text="Copy", width=8,
                      command=lambda: [pyperclip.copy(username_var.get()),
                                      self.status_var.set("Username copied to clipboard")]).\
                      grid(row=0, column=2, padx=5)
            
            # Password
            ttk.Label(details_frame, text="Password:").grid(row=1, column=0, 
                                                          sticky=tk.W, pady=5)
            password_var = tk.StringVar(value=entry["password"])
            password_entry = ttk.Entry(details_frame, textvariable=password_var, 
                                      width=30, show="•", state="readonly")
            password_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
            
            # Password visibility toggle
            show_password_var = tk.BooleanVar()
            ttk.Checkbutton(details_frame, text="Show", 
                           variable=show_password_var, 
                           command=lambda: password_entry.config(
                               show="" if show_password_var.get() else "•"
                           )).grid(row=1, column=2, sticky=tk.W)
            
            ttk.Button(details_frame, text="Copy", width=8,
                      command=lambda: [pyperclip.copy(password_var.get()),
                                      self.status_var.set("Password copied to clipboard")]).\
                      grid(row=1, column=3, padx=5)
            
            # Close button
            ttk.Button(details_window, text="Close", 
                      command=details_window.destroy).pack(pady=10)
    
    def show_context_menu(self, event):
        """Show context menu on right-click"""
        selection = self.password_tree.selection()
        if selection:
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_field(self, field):
        """Copy username or password to clipboard"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        service = self.password_tree.item(item, "values")[0]
        entry = self.password_manager.get_password(service)
        
        if entry:
            pyperclip.copy(entry[field])
            self.status_var.set(f"{field.capitalize()} copied to clipboard")
    
    def edit_selected(self):
        """Edit the selected password entry"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        service = self.password_tree.item(item, "values")[0]
        entry = self.password_manager.get_password(service)
        
        if entry:
            edit_window = tk.Toplevel(self.root)
            edit_window.title(f"Edit Password - {service}")
            edit_window.geometry("400x200")
            edit_window.resizable(False, False)
            edit_window.transient(self.root)
            edit_window.grab_set()
            
            ttk.Label(edit_window, text=f"Edit {service}", 
                     font=("Helvetica", 12)).grid(row=0, column=0, 
                                                columnspan=2, 
                                                pady=10, padx=10)
            
            # Username
            ttk.Label(edit_window, text="Username:").grid(row=1, column=0, 
                                                        sticky=tk.W, pady=5, padx=10)
            username_var = tk.StringVar(value=entry["username"])
            ttk.Entry(edit_window, textvariable=username_var, width=30).grid(row=1, column=1, 
                                                                           pady=5, padx=10)
            
            # Password
            ttk.Label(edit_window, text="Password:").grid(row=2, column=0, 
                                                        sticky=tk.W, pady=5, padx=10)
            password_var = tk.StringVar(value=entry["password"])
            password_entry = ttk.Entry(edit_window, textvariable=password_var, 
                                      width=30, show="•")
            password_entry.grid(row=2, column=1, pady=5, padx=10)
            
            # Password visibility toggle
            show_password_var = tk.BooleanVar()
            ttk.Checkbutton(edit_window, text="Show Password", 
                           variable=show_password_var, 
                           command=lambda: password_entry.config(
                               show="" if show_password_var.get() else "•"
                           )).grid(row=3, column=1, sticky=tk.W, pady=5, padx=10)
            
            # Buttons
            button_frame = ttk.Frame(edit_window)
            button_frame.grid(row=4, column=0, columnspan=2, pady=15)
            
            ttk.Button(button_frame, text="Save", 
                      command=lambda: self.save_edit(
                          edit_window,
                          service,
                          username_var.get(),
                          password_var.get()
                      )).pack(side=tk.LEFT, padx=5)
            
            ttk.Button(button_frame, text="Cancel", 
                      command=edit_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def save_edit(self, window, service, username, password):
        """Save edited password entry"""
        if not username or not password:
            messagebox.showerror("Error", "All fields are required", parent=window)
            return
        
        self.password_manager.add_password(service, username, password)
        self.password_manager.save()
        window.destroy()
        self.load_passwords()
        
        self.status_var.set(f"Updated password for {service}")
    
    def delete_selected(self):
        """Delete the selected password entry"""
        selection = self.password_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        service = self.password_tree.item(item, "values")[0]
        
        if messagebox.askyesno("Confirm Delete", 
                             f"Are you sure you want to delete the entry for {service}?"):
            if service in self.password_manager.passwords:
                del self.password_manager.passwords[service]
                self.password_manager.save()
                self.load_passwords()
                self.status_var.set(f"Deleted password for {service}")
    
    def on_close(self):
        """Handle application close"""
        if self.is_logged_in:
            self.password_manager.save()
        self.root.destroy()

class PasswordManager:
    def __init__(self, file_path="passwords.enc"):
        self.file_path = file_path
        self.passwords = {}
        self.salt = None
        self.master_key = None
    
    def generate_master_key(self, master_password):
        """Generate a secure key from the master password using PBKDF2"""
        if not self.salt:
            self.salt = os.urandom(16)  # Generate a random salt
        
        # Use PBKDF2 with high iteration count for key stretching
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        
        # Derive the key from the password
        self.master_key = kdf.derive(master_password.encode())
    
    def encrypt_data(self, data):
        """Encrypt data with AES-GCM"""
        if not self.master_key:
            raise ValueError("Master key not initialized")
        
        # Convert data to JSON string
        data_json = json.dumps(data)
        
        # Generate a random nonce for AES-GCM
        nonce = os.urandom(12)
        
        # Encrypt the data
        aesgcm = AESGCM(self.master_key)
        ciphertext = aesgcm.encrypt(nonce, data_json.encode(), None)
        
        # Combine nonce and ciphertext for storage
        encrypted_data = {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "salt": base64.b64encode(self.salt).decode()
        }
        
        return encrypted_data
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data with AES-GCM"""
        if not self.master_key:
            raise ValueError("Master key not initialized")
        
        # Get the nonce and ciphertext
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        
        # Decrypt the data
        aesgcm = AESGCM(self.master_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Parse the JSON data
        return json.loads(plaintext.decode())
    
    def save(self):
        """Save encrypted password data to file"""
        if not self.passwords:
            return
            
        encrypted_data = self.encrypt_data(self.passwords)
        
        with open(self.file_path, "w") as f:
            json.dump(encrypted_data, f)
    
    def load(self, master_password):
        """Load and decrypt password data from file"""
        try:
            with open(self.file_path, "r") as f:
                encrypted_data = json.load(f)
            
            # Load the salt
            self.salt = base64.b64decode(encrypted_data["salt"])
            
            # Generate the master key
            self.generate_master_key(master_password)
            
            # Decrypt the data
            self.passwords = self.decrypt_data(encrypted_data)
            
            return True
        except (FileNotFoundError, json.JSONDecodeError, ValueError):
            return False
    
    def add_password(self, service, username, password):
        """Add or update a password entry"""
        self.passwords[service] = {
            "username": username,
            "password": password
        }
    
    def get_password(self, service):
        """Retrieve a password entry"""
        return self.passwords.get(service)
    
    def generate_password(self, length=16):
        """Generate a strong random password"""
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
        return ''.join(secrets.choice(charset) for _ in range(length))

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()