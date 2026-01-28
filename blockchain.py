import hashlib
import json
import time
from datetime import datetime
from typing import List, Dict, Any

class Block:
    def __init__(self, index: int, transactions: List[Dict], timestamp: float, previous_hash: str, nonce: int = 0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True, default=str)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty: int) -> None:
        while self.hash[:difficulty] != '0' * difficulty:
            self.nonce += 1
            self.hash = self.compute_hash()

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.difficulty = 2
        self.pending_transactions: List[Dict] = []
        self.mining_reward = 1
        self.create_genesis_block()

    def create_genesis_block(self) -> None:
        if len(self.chain) == 0:
            genesis_block = Block(0, ["Genesis Block"], time.time(), "0")
            genesis_block.mine_block(self.difficulty)
            self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_transaction(self, transaction: Dict) -> None:
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, mining_reward_address: str) -> None:
        if not self.pending_transactions:
            return
            
        block = Block(
            len(self.chain),
            self.pending_transactions.copy(),
            time.time(),
            self.get_latest_block().hash
        )
        block.mine_block(self.difficulty)
        
        self.chain.append(block)
        self.pending_transactions = []

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            if current_block.hash != current_block.compute_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def grant_access(self, owner_did: str, target_did: str, duration: int) -> Dict:
        # Ensure duration is integer
        duration = int(duration)
        
        transaction = {
            'type': 'ACCESS_GRANT',
            'owner_did': owner_did,
            'target_did': target_did,
            'duration': duration,
            'timestamp': datetime.now().isoformat(),
            'expires_at': (datetime.now().timestamp() + duration)
        }
        
        self.add_transaction(transaction)
        self.mine_pending_transactions(owner_did)
        
        return transaction

    def revoke_access(self, owner_did: str, target_did: str) -> Dict:
        transaction = {
            'type': 'ACCESS_REVOKE',
            'owner_did': owner_did,
            'target_did': target_did,
            'timestamp': datetime.now().isoformat()
        }
        
        self.add_transaction(transaction)
        self.mine_pending_transactions(owner_did)
        
        return transaction

    def get_user_access_grants(self, user_did: str) -> List[Dict]:
        grants = []
        for block in self.chain:
            if hasattr(block, 'transactions'):
                for transaction in block.transactions:
                    if (isinstance(transaction, dict) and 
                        transaction.get('type') == 'ACCESS_GRANT' and 
                        transaction.get('owner_did') == user_did):
                        grants.append(transaction)
        return grants

    def verify_access(self, user_did: str, resource_did: str) -> bool:
        for block in reversed(self.chain):
            if hasattr(block, 'transactions'):
                for transaction in block.transactions:
                    if (isinstance(transaction, dict) and 
                        transaction.get('type') == 'ACCESS_GRANT' and 
                        transaction.get('owner_did') == resource_did and 
                        transaction.get('target_did') == user_did):
                        
                        # Check if grant is still valid
                        expires_at = transaction.get('expires_at', 0)
                        if time.time() < expires_at:
                            return True
                            
                    elif (isinstance(transaction, dict) and 
                          transaction.get('type') == 'ACCESS_REVOKE' and 
                          transaction.get('owner_did') == resource_did and 
                          transaction.get('target_did') == user_did):
                        return False
                    
        return False