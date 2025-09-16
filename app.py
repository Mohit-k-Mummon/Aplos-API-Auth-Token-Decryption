import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

# === Configuration ===
client_id = "Enter client_id here"
private_key_path = "./private.pem"

# === Step 1: Request encrypted token from Aplos ===
url = f"https://app.aplos.com/hermes/api/v1/auth/{client_id}"
response = requests.get(url)
data = response.json()

if response.status_code != 200:
    print("Error fetching token:", data)
    exit()

encrypted_token_b64 = data["data"]["token"]

# === Step 2: Load your private key ===
with open(private_key_path, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None  # Set password if your key is encrypted
    )

# === Step 3: Decrypt the token ===
encrypted_token = base64.b64decode(encrypted_token_b64)
decrypted_token = private_key.decrypt(
    encrypted_token,
    padding.PKCS1v15()  # Aplos uses RSA/ECB/PKCS1Padding (compatible with PKCS1v15)
)

token_str = decrypted_token.decode("utf-8")
print("Decrypted Access Token:\n", token_str)