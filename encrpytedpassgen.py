import os
import random
import string
import re
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# Generate a random password
def generate_password(length=16):
    if length < 16:
        raise ValueError("Password length should be at least 16 characters for strong security.")
    
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    punctuation = string.punctuation

    # Ensure the password includes at least one character from each set
    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
        random.choice(punctuation)
    ]
    
    # Fill the rest of the password length with random choices
    all_characters = uppercase + lowercase + digits + punctuation
    password += random.choices(all_characters, k=length - 4)
    
    # Shuffle the password
    random.shuffle(password)
    return ''.join(password)

# Password strength analysis
def password_strength(password):
    length_criteria = len(password) >= 16
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    digit_criteria = bool(re.search(r'[0-9]', password))
    special_char_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    common_patterns = ['1234', 'password', 'qwerty', 'admin']
    pattern_criteria = not any(pattern in password.lower() for pattern in common_patterns)

    score = sum([length_criteria, uppercase_criteria, lowercase_criteria, digit_criteria, special_char_criteria, pattern_criteria])
    feedback = []
    if not length_criteria:
        feedback.append("Increase the password length to at least 16 characters.")
    if not uppercase_criteria:
        feedback.append("Include at least one uppercase letter.")
    if not lowercase_criteria:
        feedback.append("Include at least one lowercase letter.")
    if not digit_criteria:
        feedback.append("Include at least one digit.")
    if not special_char_criteria:
        feedback.append("Include at least one special character (e.g., !, @, #).")
    if not pattern_criteria:
        feedback.append("Avoid common patterns like '1234', 'password', or 'qwerty'.")

    strength = "Weak"
    if score == 6:
        strength = "Very Strong"
    elif score >= 4:
        strength = "Strong"
    elif score >= 3:
        strength = "Moderate"

    return strength, feedback

# RSA key generation
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
    return private_key_pem, public_key_pem

# Encrypt password for sharing
def encrypt_password_for_sharing(password, recipient_public_key_pem):
    public_key = serialization.load_pem_public_key(recipient_public_key_pem)
    encrypted_password = public_key.encrypt(
        password.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_password

# Decrypt received password
def decrypt_received_password(encrypted_password, recipient_private_key_pem):
    private_key = serialization.load_pem_private_key(recipient_private_key_pem, password=None)
    decrypted_password = private_key.decrypt(
        encrypted_password,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_password.decode()

# Encrypted backup
def encrypt_backup(data, key_file="key.key", backup_file="backup.enc"):
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as key_out:
            key_out.write(key)
    else:
        with open(key_file, "rb") as key_in:
            key = key_in.read()
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data.encode())
    with open(backup_file, "wb") as backup_out:
        backup_out.write(encrypted_data)

def decrypt_backup(key_file="key.key", backup_file="backup.enc"):
    with open(key_file, "rb") as key_in:
        key = key_in.read()
    cipher = Fernet(key)
    with open(backup_file, "rb") as backup_in:
        encrypted_data = backup_in.read()
    return cipher.decrypt(encrypted_data).decode()

# Example Usage
if __name__ == "__main__":
    generated_password = generate_password(24)
    print("Generated Password:", generated_password)
    strength, suggestions = password_strength(generated_password)
    print(f"Password Strength: {strength}")
    if suggestions:
        print("Suggestions:")
        for suggestion in suggestions:
            print(f"- {suggestion}")

    # Secure sharing
    private_key, public_key = generate_rsa_keys()
    encrypted_password = encrypt_password_for_sharing(generated_password, public_key)
    print("Encrypted Password for Sharing:", encrypted_password)
    decrypted_password = decrypt_received_password(encrypted_password, private_key)
    print("Decrypted Password:", decrypted_password)

    # Backup
    encrypt_backup(generated_password)
    decrypted_backup = decrypt_backup()
    print("Decrypted Backup:", decrypted_backup)