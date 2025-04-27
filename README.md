# SecurePass Manager

A secure, encrypted password manager application built with Python and Tkinter.



## Features

- **Strong Encryption**: AES-GCM encryption for all stored passwords
- **Master Password Protection**: Single master password to access all your credentials
- **User-Friendly GUI**: Clean and intuitive interface built with Tkinter
- **Password Generator**: Create strong, random passwords with customizable settings
- **Search Functionality**: Quickly find stored credentials
- **Clipboard Integration**: Copy usernames and passwords with a single click
- **Portable**: Can be used from any device with the encrypted file

## Security Features

- **AES-GCM Encryption**: Industry-standard authenticated encryption
- **PBKDF2 Key Derivation**: 100,000 iterations with SHA-256 for master password security
- **No Plain-Text Storage**: Passwords are never stored in plain text
- **Local Storage**: All data remains on your device, not in the cloud
- **Secure Random Generation**: Cryptographically secure random password generation

## Installation

### Prerequisites
- Python 3.6 or higher
- Required packages: `cryptography`, `pyperclip`

### Setup
1. Clone this repository:
   ```
   git clone https://github.com/tinmarco/PasswordManager
   cd PasswordManager
   ```

2. Install required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python PasswordManager.py
   ```

## Usage

### First-Time Setup
1. Run the application
2. Create a strong master password
3. Start adding your passwords

### Adding Passwords
1. Click "Add Password" 
2. Enter the service name, username, and password
3. Click "Save"

### Generating Strong Passwords
1. Click "Generate Password"
2. Adjust length and character options
3. Click "Generate"
4. Copy the generated password or use it directly when adding a new entry

### Retrieving Passwords
1. Select an entry from the list or use the search function
2. Double-click an entry to view details
3. Use the "Copy" buttons or right-click for context menu options

## Security Best Practices

For maximum security, please follow these guidelines:

1. **Create a Strong Master Password**: Use a long, complex master password that you don't use anywhere else
2. **Regular Backups**: Keep secure backups of your `passwords.enc` file
3. **Keep Your System Secure**: Ensure your computer is free of malware and keyloggers
4. **Lock When Away**: Close the application when not in use
5. **Update Regularly**: Keep Python and all dependencies updated

## Project Structure

PasswordManager/
├── PasswordManger.py     # Main application file
├── requirements.txt  # Required packages
├── .gitignore        # Git ignore file
├── README.md         # This readme file
└── passwords.enc     # Encrypted password database (created after first use)
```

## Technical Implementation

- **Encryption**: Uses `cryptography` library with AES-GCM mode
- **Key Derivation**: PBKDF2HMAC with SHA-256 and 100,000 iterations
- **GUI**: Built with Tkinter for cross-platform compatibility
- **Storage Format**: JSON-based encrypted file format

## Development Roadmap

Future improvements planned:

- [ ] Automatic timeout/lock feature
- [ ] Multi-factor authentication
- [ ] Password strength analysis
- [ ] Secure password sharing
- [ ] Audit logging
- [ ] Dark mode theme
- [ ] Mobile companion app

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This password manager was created as a security learning project. While it implements strong encryption and security best practices, no software can guarantee absolute security. Use at your own risk.

---

Created by Marco Tinoco - https://github.com/tinmarco