import secrets

# Generates a secure random key (32 bytes -> 64 hexadecimal characters)
secret_key = secrets.token_hex(32)
print(f"Your secret key: {secret_key}")