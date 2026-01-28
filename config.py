import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DATABASE = 'vpn_database.db'
    WIREGUARD_SERVER_PUBLIC_KEY = 'SERVER_PUBLIC_KEY_PLACEHOLDER'
    WIREGUARD_SERVER_ENDPOINT = 'vpn.example.com:51820'
    BLOCKCHAIN_DIFFICULTY = 2