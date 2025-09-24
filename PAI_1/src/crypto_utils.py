import hashlib
import hmac
import secrets
import json

# Clave compartida para MAC (256 bits = 32 bytes)
# En un entorno real, se compartiría de forma segura (Objetivo 4 del PAI)
SHARED_KEY = b"clave_secreta_256_bits_segura_PA1"  # 32 bytes exactos

def hash_password(password: str, salt: str = None) -> tuple:
    """Genera un hash seguro de la contraseña con sal (PBKDF2-HMAC-SHA256)."""
    if salt is None:
        salt = secrets.token_hex(32)  # 256 bits de sal
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return pwd_hash.hex(), salt

def verify_password(stored_hash: str, stored_salt: str, password: str) -> bool:
    """Verifica una contraseña usando hash almacenado y sal."""
    pwd_hash, _ = hash_password(password, stored_salt)
    return hmac.compare_digest(pwd_hash, stored_hash)

def generate_nonce() -> str:
    """Genera un NONCE único (128 bits)."""
    return secrets.token_hex(16)

def compute_mac(data: str, nonce: str) -> str:
    """Calcula HMAC-SHA256 del mensaje + nonce usando la clave compartida."""
    message = data + nonce
    mac = hmac.new(SHARED_KEY, message.encode(), hashlib.sha256).hexdigest()
    return mac

def verify_mac(data: str, nonce: str, received_mac: str) -> bool:
    """Verifica la integridad del mensaje usando MAC."""
    expected_mac = compute_mac(data, nonce)
    return hmac.compare_digest(expected_mac, received_mac)
