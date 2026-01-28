import sqlite3
import hashlib
import os
from datetime import datetime

def get_db_connection():
    conn = sqlite3.connect('vpn_database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    
    # Users table with DID document
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            did TEXT UNIQUE NOT NULL,
            did_document TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Access logs table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action_type TEXT NOT NULL,
            description TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # WireGuard configurations table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS wireguard_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL,
            server_public_key TEXT NOT NULL,
            server_endpoint TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            dns_servers TEXT DEFAULT '1.1.1.1',
            is_active BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Demo data table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS demo_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_users INTEGER DEFAULT 0,
            total_blocks INTEGER DEFAULT 0,
            total_transactions INTEGER DEFAULT 0,
            vpn_connections INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert initial demo stats
    conn.execute('''
        INSERT OR IGNORE INTO demo_stats (id, total_users, total_blocks, total_transactions, vpn_connections)
        VALUES (1, 0, 1, 0, 0)
    ''')
    
    # Notifications table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            notification_type TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            related_did TEXT,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def log_access_attempt(user_id, action_type, description, ip_address=None):
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO access_logs (user_id, action_type, description, ip_address) VALUES (?, ?, ?, ?)',
        (user_id, action_type, description, ip_address)
    )
    conn.commit()
    conn.close()

def get_user_logs(user_id, limit=50):
    conn = get_db_connection()
    logs = conn.execute(
        'SELECT * FROM access_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?',
        (user_id, limit)
    ).fetchall()
    conn.close()
    return logs

def create_notification(user_id, notification_type, title, message, related_did=None):
    """Create a new notification for a user"""
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO notifications (user_id, notification_type, title, message, related_did) VALUES (?, ?, ?, ?, ?)',
        (user_id, notification_type, title, message, related_did)
    )
    conn.commit()
    conn.close()

def get_user_notifications(user_id, limit=10, unread_only=False):
    """Get notifications for a user"""
    conn = get_db_connection()
    
    if unread_only:
        notifications = conn.execute(
            'SELECT * FROM notifications WHERE user_id = ? AND is_read = FALSE ORDER BY created_at DESC LIMIT ?',
            (user_id, limit)
        ).fetchall()
    else:
        notifications = conn.execute(
            'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
            (user_id, limit)
        ).fetchall()
    
    conn.close()
    return notifications

def mark_notification_read(notification_id):
    """Mark a notification as read"""
    conn = get_db_connection()
    conn.execute(
        'UPDATE notifications SET is_read = TRUE WHERE id = ?',
        (notification_id,)
    )
    conn.commit()
    conn.close()

def mark_all_notifications_read(user_id):
    """Mark all notifications as read for a user"""
    conn = get_db_connection()
    conn.execute(
        'UPDATE notifications SET is_read = TRUE WHERE user_id = ?',
        (user_id,)
    )
    conn.commit()
    conn.close()

def get_unread_notification_count(user_id):
    """Get count of unread notifications for a user"""
    conn = get_db_connection()
    count = conn.execute(
        'SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = FALSE',
        (user_id,)
    ).fetchone()[0]
    conn.close()
    return count