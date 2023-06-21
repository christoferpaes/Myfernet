from cryptography.fernet import Fernet

# Generate a random encryption key
encryption_key = Fernet.generate_key()

# Create a Fernet cipher object with the encryption key
cipher = Fernet(encryption_key)

# Encrypt the payload
payload = b"Hello, world!"
encrypted_payload = cipher.encrypt(payload)

# Decrypt the payload
decrypted_payload = cipher.decrypt(encrypted_payload)

# Print the original and decrypted payloads
print("Original Payload:", payload)
print("Decrypted Payload:", decrypted_payload)
