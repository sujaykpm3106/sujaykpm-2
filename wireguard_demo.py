import sqlite3
import secrets
import base64
import os
import random
from database import get_db_connection

class WireGuardDemoManager:
    def __init__(self):
        self.config_dir = "wireguard_configs"
        self.server_public_key = "oNf1Y6cB8q3jK7mPxZwR9tSvL2aH5nJ8gT0yV3bC6dE="
        self.server_private_key = "qAb2cD4eF6gH8iJ0kL1mN3oP5qR7sT9uV0wX2yZ4aB="
        self.server_endpoint = "vpn.zerotrust-demo.com:51820"
        self.server_ip = "10.0.0.1"
        self.subnet = "10.0.0.0/24"
        self.is_running = False
        
        # Create config directory
        os.makedirs(self.config_dir, exist_ok=True)

    def generate_keypair(self):
        """Generate simulated WireGuard key pair"""
        # Generate random keys for demo (base64 encoded random bytes)
        private_key = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
        public_key = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
        return private_key, public_key

    def get_user_config(self, user_id):
        conn = get_db_connection()
        config = conn.execute(
            'SELECT * FROM wireguard_configs WHERE user_id = ?', (user_id,)
        ).fetchone()
        conn.close()
        
        if not config:
            return self.create_user_config(user_id)
        
        return config

    def create_user_config(self, user_id):
        private_key, public_key = self.generate_keypair()
        client_ip = f"10.0.0.{user_id + 100}/32"
        
        conn = get_db_connection()
        try:
            conn.execute(
                '''INSERT INTO wireguard_configs 
                   (user_id, private_key, public_key, server_public_key, server_endpoint, client_ip) 
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (user_id, private_key, public_key, self.server_public_key, self.server_endpoint, client_ip)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # Config already exists, just return it
            pass
        
        config = conn.execute(
            'SELECT * FROM wireguard_configs WHERE user_id = ?', (user_id,)
        ).fetchone()
        conn.close()
        
        return config

    def generate_config_file(self, user_id):
        """Generate WireGuard configuration file content"""
        config = self.get_user_config(user_id)
        user_did = self.get_user_did(user_id)
        
        config_content = f"""# Zero-Trust VPN Configuration
# Generated for: User ID {user_id}
# Decentralized Identity: {user_did}

[Interface]
PrivateKey = {config['private_key']}
Address = {config['client_ip']}
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = {config['server_public_key']}
Endpoint = {config['server_endpoint']}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25

# === ZERO-TRUST VPN DEMO ===
# This configuration demonstrates:
# - Blockchain-based identity verification
# - Zero-Trust security principles
# - WireGuard VPN protocol integration
# - Decentralized access control via smart contracts

# Your access is managed through blockchain smart contracts
# All connections are verified against the distributed ledger

# To use in production:
# 1. Install WireGuard from https://www.wireguard.com/install/
# 2. Import this configuration
# 3. Connect to the Zero-Trust VPN network

# Security Features:
# ✅ End-to-end encryption
# ✅ Blockchain authentication
# ✅ Zero-Trust verification
# ✅ Immutable access logs
"""
        
        # Save to file for download
        config_path = os.path.join(self.config_dir, f"wg0-client-{user_id}.conf")
        with open(config_path, 'w') as f:
            f.write(config_content)
            
        return config_content

    def get_user_did(self, user_id):
        """Get user's DID for the config file"""
        conn = get_db_connection()
        user = conn.execute('SELECT did FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        return user['did'] if user else "Unknown DID"

    def enable_vpn(self, user_id):
        """Enable VPN for user (demo simulation)"""
        conn = get_db_connection()
        conn.execute(
            'UPDATE wireguard_configs SET is_active = TRUE WHERE user_id = ?',
            (user_id,)
        )
        conn.commit()
        conn.close()
        
        # Simulate starting WireGuard
        self.is_running = True
        
        return {
            'status': 'enabled', 
            'message': '✅ VPN connection activated (Demo Mode)',
            'server_status': 'running',
            'client_ip': f'10.0.0.{user_id + 100}',
            'data_transferred': f'{random.randint(10, 100)} MB'
        }

    def disable_vpn(self, user_id):
        """Disable VPN for user (demo simulation)"""
        conn = get_db_connection()
        conn.execute(
            'UPDATE wireguard_configs SET is_active = FALSE WHERE user_id = ?',
            (user_id,)
        )
        conn.commit()
        conn.close()
        
        return {
            'status': 'disabled', 
            'message': '🔒 VPN connection deactivated',
            'server_status': 'stopped'
        }

    def get_user_status(self, user_id):
        """Get user's VPN status"""
        try:
            config = self.get_user_config(user_id)
            if config and config['is_active']:
                return 'active'
            return 'inactive'
        except:
            return 'inactive'

    def start_wireguard(self):
        """Start WireGuard server (demo simulation)"""
        self.is_running = True
        
        # Create a demo server status
        server_config = f"""[Interface]
PrivateKey = {self.server_private_key}
Address = {self.server_ip}/24
ListenPort = 51820
SaveConfig = false

# Zero-Trust VPN Demo Server
# Blockchain-authenticated VPN endpoint
# All connections verified via smart contracts
"""
        
        config_path = os.path.join(self.config_dir, "wg0-server.conf")
        with open(config_path, 'w') as f:
            f.write(server_config)
        
        return True

    def get_server_status(self):
        """Get WireGuard server status (demo simulation)"""
        if self.is_running:
            return f"""interface: wg0
  public key: {self.server_public_key}
  private key: (hidden)
  listening port: 51820

peer: demo-client-1
  endpoint: 203.0.113.1:51820
  allowed ips: 10.0.0.101/32
  latest handshake: 1 minute, 17 seconds ago
  transfer: 15.30 MiB received, 5.21 MiB sent
  blockchain verified: ✅

peer: demo-client-2  
  endpoint: 203.0.113.2:51820
  allowed ips: 10.0.0.102/32
  latest handshake: 2 minutes, 5 seconds ago
  transfer: 8.45 MiB received, 12.10 MiB sent
  blockchain verified: ✅

# DEMO MODE: Zero-Trust VPN Server
# All connections authenticated via blockchain
# Smart contract access control active
# Total active clients: {random.randint(2, 8)}"""
        else:
            return """WireGuard is not running (Demo Mode)

To start the VPN server in production:
1. Install WireGuard on your system
2. Use the generated configuration files  
3. Start the wg-quick service

Current system: Zero-Trust VPN Demo
- Blockchain authentication: ✅ Ready
- Smart contracts: ✅ Deployed
- DID verification: ✅ Active
- Access control: ✅ Enabled"""