import unittest
import os
from main import caesar_encrypt, caesar_decrypt, load_passwords, save_passwords, add_password, retrieve_password

# This test suite includes tests for the Caesar cipher encryption and decryption,
# loading and saving passwords from/to a file, and adding and retrieving passwords in the password manager. 
# One can adapt and expand these tests based on the specific features and functions of the password manager.

class TestPasswordManager(unittest.TestCase):

    def setUp(self):
        # Create a temporary passwords.txt file for testing
        self.test_passwords_file = "test_passwords.txt"
        self.test_passwords = {
            "example_username": "EncryptedPassword123",
            "test_user": "EncryptedTestPassword"
        }
        save_passwords(self.test_passwords, self.test_passwords_file)

    def tearDown(self):
        # Remove the temporary passwords.txt file after testing
        os.remove(self.test_passwords_file)

    def test_caesar_encrypt_decrypt(self):
        # Test Caesar cipher encryption and decryption
        original_text = "SecretPassword123"
        shift = 5

        # Encrypt the text
        encrypted_text = caesar_encrypt(original_text, shift)
        self.assertNotEqual(original_text, encrypted_text)  # Encrypted text should be different

        # Decrypt the text
        decrypted_text = caesar_decrypt(encrypted_text, shift)
        self.assertEqual(original_text, decrypted_text)

    def test_load_passwords(self):
        # Test loading passwords from an existing file
        loaded_passwords = load_passwords(self.test_passwords_file)
        self.assertEqual(loaded_passwords, self.test_passwords)

        # Test loading passwords from a non-existent file
        nonexistent_file = "nonexistent.txt"
        loaded_passwords = load_passwords(nonexistent_file)
        self.assertEqual(loaded_passwords, {})

    def test_save_passwords(self):
        # Save passwords to a temporary file
        temp_passwords_file = "temp_passwords.txt"
        temp_passwords = {
            "user1": "EncryptedPassword1",
            "user2": "EncryptedPassword2"
        }
        save_passwords(temp_passwords, temp_passwords_file)

        # Check if the saved passwords match the original passwords
        loaded_passwords = load_passwords(temp_passwords_file)
        self.assertEqual(loaded_passwords, temp_passwords)

        # Remove the temporary file after testing
        os.remove(temp_passwords_file)

    def test_add_and_retrieve_password(self):
        # Test adding a password and retrieving it
        key = "new_user"
        password = "NewEncryptedPassword"
        add_password(self.test_passwords, key, password)

        # Check if the added password is in the dictionary
        self.assertIn(key, self.test_passwords)

        # Retrieve the added password
        retrieved_password = retrieve_password(self.test_passwords, key)
        self.assertEqual(retrieved_password, password)

if __name__ == '__main__':
    unittest.main()
