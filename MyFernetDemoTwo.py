from scapy.all import *
from cryptography.fernet import Fernet

# Define the Fernet key
fernet_key = b'your_fernet_key_here'  # Replace with your own Fernet key

# Create an ICMP packet with encrypted payload
plaintext_payload = "Hello, World!"  # Modify this plaintext payload as needed

# Create a Fernet object with the key
fernet = Fernet(fernet_key)

# Encrypt the plaintext payload
encrypted_payload = fernet.encrypt(plaintext_payload.encode())

# Create the packet with the encrypted payload
packet = IP(dst="192.168.0.1") / ICMP() / encrypted_payload

# Send the packet
send(packet)

# Retrieve the captured packet with encrypted payload
captured_packet = sniff(count=1)[0]

# Extract the encrypted payload from the captured packet
captured_payload = captured_packet.load

# Decrypt the captured payload
decrypted_payload = fernet.decrypt(captured_payload).decode()

# Print the decrypted payload
print("Decrypted Payload:", decrypted_payload)
