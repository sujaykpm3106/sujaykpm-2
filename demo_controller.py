from database import get_db_connection
from blockchain import Blockchain
from wireguard_real import WireGuardRealManager  # Use real manager
import json
from datetime import datetime

class DemoController:
    def __init__(self):
        self.blockchain = Blockchain()
        self.wg_manager = WireGuardRealManager()  # Use real manager
    
    def get_demo_stats(self):
        conn = get_db_connection()
        stats = conn.execute('SELECT * FROM demo_stats WHERE id = 1').fetchone()
        conn.close()
        return dict(stats) if stats else {}
    
    def update_demo_stats(self):
        conn = get_db_connection()
        
        # Count users
        user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        
        # Count blocks and transactions
        block_count = len(self.blockchain.chain)
        transaction_count = sum(len(block.transactions) for block in self.blockchain.chain)
        
        # Count active VPN connections
        vpn_count = conn.execute('SELECT COUNT(*) FROM wireguard_configs WHERE is_active = TRUE').fetchone()[0]
        
        conn.execute('''
            UPDATE demo_stats 
            SET total_users = ?, total_blocks = ?, total_transactions = ?, vpn_connections = ?, last_updated = ?
            WHERE id = 1
        ''', (user_count, block_count, transaction_count, vpn_count, datetime.now()))
        
        conn.commit()
        conn.close()
    
    def create_demo_scenario(self):
        """Create a demonstration scenario with sample data"""
        # Create sample access grants
        sample_grants = [
            {
                "owner_did": "did:vpn:blockchain:demoowner123456789",
                "target_did": "did:vpn:blockchain:demotarget456789012",
                "duration": 7200,
                "purpose": "IoT Device Access",
                "timestamp": datetime.now().isoformat()
            },
            {
                "owner_did": "did:vpn:blockchain:company789012345678",
                "target_did": "did:vpn:blockchain:employee00123456789", 
                "duration": 28800,
                "purpose": "Remote Work Access",
                "timestamp": datetime.now().isoformat()
            }
        ]
        
        return {
            "sample_grants": sample_grants,
            "blockchain_info": {
                "total_blocks": len(self.blockchain.chain),
                "total_transactions": sum(len(block.transactions) for block in self.blockchain.chain),
                "chain_valid": self.blockchain.is_chain_valid()
            },
            "wireguard_status": self.wg_manager.get_server_status(),
            "wireguard_installed": True  # Since you installed it
        }