import sqlite3
import hashlib
import secrets
import json
from datetime import datetime
from database import get_db_connection
import base64
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_did():
    """Generate a proper Decentralized Identifier with key material"""
    did_method = "vpn"
    did_method_specific_id = secrets.token_hex(16)  # 32 characters
    
    # Generate key material for the DID
    verification_key = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
    authentication_key = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
    
    did = f"did:{did_method}:{did_method_specific_id}"
    
    # Create DID Document
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "created": datetime.now().isoformat() + "Z",
        "verificationMethod": [{
            "id": f"{did}#keys-1",
            "type": "Ed25519VerificationKey2020", 
            "controller": did,
            "publicKeyMultibase": f"z{verification_key}"
        }],
        "authentication": [
            f"{did}#keys-1"
        ],
        "assertionMethod": [
            f"{did}#keys-1"
        ],
        "service": [{
            "id": f"{did}#vpn-service",
            "type": "ZeroTrustVPN",
            "serviceEndpoint": "https://vpn-service.example.com",
            "description": "Zero-Trust VPN Access Service"
        }]
    }
    
    return did, json.dumps(did_document, indent=2)

def register_user(username, password, email):
    conn = get_db_connection()
    
    # Check if username exists
    existing_user = conn.execute(
        'SELECT id FROM users WHERE username = ?', (username,)
    ).fetchone()
    
    if existing_user:
        conn.close()
        return False
    
    # Create new user with DID
    password_hash = hash_password(password)
    did, did_document = generate_did()
    
    try:
        conn.execute(
            'INSERT INTO users (username, password_hash, email, did, did_document) VALUES (?, ?, ?, ?, ?)',
            (username, password_hash, email, did, did_document)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError as e:
        print(f"Registration error: {e}")
        conn.close()
        return False

def authenticate_user(username, password):
    conn = get_db_connection()
    
    user = conn.execute(
        'SELECT * FROM users WHERE username = ? AND password_hash = ?',
        (username, hash_password(password))
    ).fetchone()
    
    conn.close()
    return user

def get_user_did(user_id):
    conn = get_db_connection()
    user = conn.execute(
        'SELECT did FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    conn.close()
    return user['did'] if user else None

def get_user_did_document(user_id):
    conn = get_db_connection()
    user = conn.execute(
        'SELECT did_document FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    conn.close()
    if user and user['did_document']:
        try:
            return json.loads(user['did_document'])
        except:
            return {"error": "Invalid DID document format"}
    return None