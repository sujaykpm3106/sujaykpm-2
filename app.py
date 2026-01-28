from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
import sqlite3
import json
from datetime import datetime
import hashlib
import os
from blockchain import Blockchain
from auth import authenticate_user, register_user, get_user_did, get_user_did_document
from wireguard_real import WireGuardRealManager
from database import init_db, log_access_attempt, get_user_logs, get_db_connection, create_notification, get_user_notifications, mark_notification_read, mark_all_notifications_read, get_unread_notification_count
from demo_controller import DemoController

app = Flask(__name__)
app.secret_key = 'zero-trust-vpn-real-wireguard-2024'
app.config['DATABASE'] = 'vpn_database.db'

# Initialize components
blockchain = Blockchain()
wg_manager = WireGuardRealManager()
demo_controller = DemoController()

# Initialize database on startup
with app.app_context():
    init_db()
    if len(blockchain.chain) == 0:
        blockchain.create_genesis_block()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = authenticate_user(username, password)
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['did'] = user[3]
            log_access_attempt(user[0], 'LOGIN_SUCCESS', f"User {username} logged in successfully")
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            log_access_attempt(None, 'LOGIN_FAILED', f"Failed login attempt for user {username}")
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        if register_user(username, password, email):
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists!', 'error')
    
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get unread notification count for stats
    unread_count = get_unread_notification_count(session['user_id'])
    
    user_stats = {
        'vpn_status': wg_manager.get_user_status(session['user_id']),
        'access_grants': blockchain.get_user_access_grants(session['did']),
        'last_login': get_user_logs(session['user_id'])[0][3] if get_user_logs(session['user_id']) else 'Never',
        'unread_notifications': unread_count
    }
    
    return render_template('dashboard.html', stats=user_stats)

@app.route('/blockchain')
def blockchain_view():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    chain_data = []
    for block in blockchain.chain:
        chain_data.append({
            'index': block.index,
            'timestamp': datetime.fromtimestamp(block.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            'transactions': block.transactions,
            'previous_hash': block.previous_hash,
            'hash': block.hash,
            'nonce': block.nonce
        })
    
    return render_template('blockchain.html', chain=chain_data)

@app.route('/wireguard')
def wireguard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_config = wg_manager.get_user_config(session['user_id'])
    config_content = wg_manager.generate_config_file(session['user_id'])
    server_status = wg_manager.get_server_status()
    
    # Validate configuration
    validation = wg_manager.validate_configuration(session['user_id'])
    
    return render_template('wireguard.html', 
                         config=user_config, 
                         config_content=config_content,
                         server_status=server_status,
                         validation=validation)

@app.route('/api/toggle_vpn', methods=['POST'])
def toggle_vpn():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    action = request.json.get('action')
    
    if action == 'enable':
        result = wg_manager.enable_vpn(user_id)
    elif action == 'disable':
        result = wg_manager.disable_vpn(user_id)
    else:
        return jsonify({'error': 'Invalid action'}), 400
    
    log_access_attempt(user_id, 'VPN_TOGGLE', f"VPN {action} for user {session['username']}")
    return jsonify(result)

@app.route('/api/grant_access', methods=['POST'])
def grant_access():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    target_did = request.json.get('target_did', '').strip()
    duration = request.json.get('duration', 3600)
    
    # Clean and validate the DID
    if not target_did:
        return jsonify({'error': 'Target DID is required'}), 400
    
    target_did = ''.join(target_did.split())
    
    if not target_did.startswith('did:vpn:'):
        return jsonify({
            'error': f'Invalid DID format. Must start with "did:vpn:" but got: {target_did[:50]}...'
        }), 400
    
    try:
        duration = int(duration)
    except (ValueError, TypeError):
        return jsonify({'error': 'Duration must be a valid number'}), 400
    
    if duration < 60:
        return jsonify({'error': 'Duration must be at least 60 seconds'}), 400
    
    try:
        # Find the target user by DID
        conn = get_db_connection()
        target_user = conn.execute(
            'SELECT id, username FROM users WHERE did = ?', 
            (target_did,)
        ).fetchone()
        conn.close()
        
        if not target_user:
            return jsonify({'error': 'User with this DID not found'}), 404
        
        # Create the blockchain transaction
        transaction = blockchain.grant_access(session['did'], target_did, duration)
        
        # Log the access attempt
        log_access_attempt(session['user_id'], 'ACCESS_GRANT', 
                          f"User {session['username']} granted access to {target_did} for {duration}s")
        
        # Create notification for the GRANTOR (you)
        create_notification(
            user_id=session['user_id'],
            notification_type='access_granted',
            title='✅ Access Granted',
            message=f'You granted VPN access to {target_user["username"]} for {duration//3600} hours',
            related_did=target_did
        )
        
        # Create notification for the GRANTEE (target user)
        create_notification(
            user_id=target_user['id'],
            notification_type='access_received',
            title='🔑 VPN Access Granted',
            message=f'{session["username"]} granted you VPN access for {duration//3600} hours',
            related_did=session['did']
        )
        
        return jsonify({
            'transaction': transaction,
            'message': f'Access granted to {target_user["username"]} for {duration} seconds',
            'target_username': target_user['username']
        })
        
    except Exception as e:
        print(f"Error in grant_access: {e}")
        return jsonify({'error': f'Failed to grant access: {str(e)}'}), 500

@app.route('/api/available_users')
def api_available_users():
    """Get all users except the current user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    try:
        users = conn.execute(
            'SELECT id, username, did FROM users WHERE id != ? ORDER BY username',
            (session['user_id'],)
        ).fetchall()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user['id'],
                'username': user['username'], 
                'did': user['did']
            })
            
        return jsonify(users_list)
        
    except Exception as e:
        print(f"Error fetching users: {e}")
        return jsonify({'error': 'Failed to fetch users'}), 500
    finally:
        conn.close()

@app.route('/api/validate_config')
def api_validate_config():
    """Validate WireGuard configuration"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    validation = wg_manager.validate_configuration(session['user_id'])
    return jsonify(validation)

@app.route('/api/notifications')
def api_notifications():
    """Get user notifications"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    notifications = get_user_notifications(session['user_id'])
    notifications_list = []
    for notification in notifications:
        notifications_list.append({
            'id': notification['id'],
            'type': notification['notification_type'],
            'title': notification['title'],
            'message': notification['message'],
            'related_did': notification['related_did'],
            'is_read': bool(notification['is_read']),
            'created_at': notification['created_at']
        })
    
    return jsonify(notifications_list)

@app.route('/api/notifications/read/<int:notification_id>', methods=['POST'])
def mark_notification_read_api(notification_id):
    """Mark a notification as read"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    mark_notification_read(notification_id)
    return jsonify({'success': True})

@app.route('/api/notifications/read_all', methods=['POST'])
def mark_all_notifications_read_api():
    """Mark all notifications as read"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    mark_all_notifications_read(session['user_id'])
    return jsonify({'success': True})

@app.route('/api/notifications/unread_count')
def unread_notification_count():
    """Get unread notification count"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    count = get_unread_notification_count(session['user_id'])
    return jsonify({'count': count})

@app.route('/demo')
def demo():
    """Demo page showing system overview"""
    demo_stats = demo_controller.get_demo_stats()
    demo_scenario = demo_controller.create_demo_scenario()
    
    return render_template('demo.html', 
                         stats=demo_stats, 
                         scenario=demo_scenario)

@app.route('/api/demo_stats')
def api_demo_stats():
    """API endpoint for demo statistics"""
    demo_controller.update_demo_stats()
    stats = demo_controller.get_demo_stats()
    return jsonify(stats)

@app.route('/did_document')
def did_document():
    """Show user's DID document"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    did_doc = get_user_did_document(session['user_id'])
    return render_template('did_document.html', did_document=did_doc)

@app.route('/api/install_service', methods=['POST'])
def api_install_service():
    """Generate WireGuard configuration (Windows-compatible)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        success = wg_manager.start_wireguard()
        return jsonify({
            'success': success,
            'message': 'WireGuard configuration generated! Download and import into WireGuard Windows application.'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/server_status')
def api_server_status():
    """Get WireGuard server status"""
    status = wg_manager.get_server_status()
    return jsonify({'status': status})

@app.route('/download_config/<int:user_id>')
def download_config(user_id):
    """Download WireGuard configuration file"""
    if 'user_id' not in session or session['user_id'] != user_id:
        return redirect(url_for('login'))
    
    config_content = wg_manager.generate_config_file(user_id)
    
    response = make_response(config_content)
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = f'attachment; filename=zerotrust-vpn-{session["username"]}.conf'
    return response

@app.route('/open_wireguard')
def open_wireguard():
    """Try to open WireGuard GUI application"""
    try:
        wireguard_paths = [
            r"C:\Program Files\WireGuard\wireguard.exe",
            r"C:\Program Files (x86)\WireGuard\wireguard.exe",
        ]
        
        for path in wireguard_paths:
            if os.path.exists(path):
                os.startfile(path)
                return jsonify({'success': True, 'message': 'Opening WireGuard application...'})
        
        # If not found, try to open via shell
        os.system('start wireguard:')
        return jsonify({'success': True, 'message': 'Attempting to open WireGuard...'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Could not open WireGuard: {str(e)}'})

@app.route('/logs')
def logs():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_logs = get_user_logs(session['user_id'])
    return render_template('logs.html', logs=user_logs)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_access_attempt(session['user_id'], 'LOGOUT', f"User {session['username']} logged out")
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# Debug route to see all users (remove in production)
@app.route('/debug/users')
def debug_users():
    """Debug route to see all users"""
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    
    users_list = []
    for user in users:
        users_list.append(dict(user))
    
    return jsonify(users_list)

if __name__ == '__main__':
    print("🚀 Starting Zero-Trust VPN with WireGuard Integration...")
    print("📁 Configuration files will be saved in: wireguard_configs/")
    print("💡 Instructions: Download .conf files and import into WireGuard Windows GUI")
    print("🌐 Access the system at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)