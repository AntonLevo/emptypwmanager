import os

# Caesar cipher encryption and decryption functions
def caesar_encrypt(text, shift):
    """
    Encrypts a given text using the Caesar cipher with the specified shift.

    Args:
        text (str): The text to be encrypted.
        shift (int): The number of positions to shift each character.

    Returns:
        str: The encrypted text.
    """
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    """
    Decrypts a given text using the Caesar cipher with the specified shift.

    Args:
        text (str): The text to be decrypted.
        shift (int): The number of positions to shift each character.

    Returns:
        str: The decrypted text.
    """
    return caesar_encrypt(text, -shift)

# File handling functions
def load_passwords(file_path):
    """
    Loads passwords from a file and returns them as a dictionary.

    Args:
        file_path (str): The path to the file containing encrypted passwords.

    Returns:
        dict: A dictionary containing key-value pairs of usernames and encrypted passwords.
    """
    passwords = {}
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            for line in file:
                key, encrypted_password = line.strip().split(':')
                passwords[key] = encrypted_password
    return passwords

def save_passwords(passwords, file_path):
    """
    Saves passwords to a file in the format "username:encrypted_password".

    Args:
        passwords (dict): A dictionary containing key-value pairs of usernames and encrypted passwords.
        file_path (str): The path to the file where passwords will be saved.
    """
    with open(file_path, 'w') as file:
        for key, encrypted_password in passwords.items():
            file.write(f"{key}:{encrypted_password}\n")

# Password manager functions
def add_password(passwords, key, password):
    """
    Adds a new password to the password dictionary.

    Args:
        passwords (dict): A dictionary containing key-value pairs of usernames and encrypted passwords.
        key (str): The username or key for the password.
        password (str): The plain text password to be encrypted and stored.
    """
    # Assume passwords are case-sensitive
    encrypted_password = caesar_encrypt(password, shift=3)
    passwords[key] = encrypted_password

def retrieve_password(passwords, key):
    """
    Retrieves a password from the password dictionary and decrypts it.

    Args:
        passwords (dict): A dictionary containing key-value pairs of usernames and encrypted passwords.
        key (str): The username or key for the password.

    Returns:
        str: The decrypted plain text password, or None if the key is not found.
    """
    if key in passwords:
        encrypted_password = passwords[key]
        return caesar_decrypt(encrypted_password, shift=3)
    else:
        return None

# Example usage
file_path = 'passwords.txt'
passwords = load_passwords(file_path)

# Add a password
add_password(passwords, 'example_username', 'example_password')

# Retrieve a password
retrieved_password = retrieve_password(passwords, 'example_username')
print(f"Retrieved Password: {retrieved_password}")

# Save passwords to file
save_passwords(passwords, file_path)
