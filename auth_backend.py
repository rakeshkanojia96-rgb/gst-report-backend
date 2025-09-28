#!/usr/bin/env python3
"""
Authentication Backend for GST Report Generator
Provides secure user registration, login, and session management
"""

import sqlite3
import hashlib
import secrets
import json
import os
from datetime import datetime, timedelta
from functools import wraps
import re

class AuthBackend:
    def __init__(self, db_path='users.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the user database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                company TEXT NOT NULL,
                gst_number TEXT,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                last_login TIMESTAMP,
                email_verified BOOLEAN DEFAULT 0
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # User preferences table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_preferences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                preference_key TEXT NOT NULL,
                preference_value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, preference_key)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password, salt=None):
        """Hash password with salt using SHA-256"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return password_hash, salt
    
    def validate_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def validate_gst_number(self, gst_number):
        """Validate GST number format (15 characters)"""
        if not gst_number:
            return True  # Optional field
        
        pattern = r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$'
        return re.match(pattern, gst_number.upper()) is not None
    
    def validate_phone(self, phone):
        """Validate Indian phone number"""
        pattern = r'^[6-9]\d{9}$'
        return re.match(pattern, phone.replace('+91', '').replace('-', '').replace(' ', '')) is not None
    
    def register_user(self, user_data):
        """Register a new user"""
        try:
            # Validate required fields
            required_fields = ['first_name', 'last_name', 'email', 'phone', 'company', 'gst_number', 'password']
            for field in required_fields:
                if not user_data.get(field) or not user_data[field].strip():
                    return {'success': False, 'message': f'{field.replace("_", " ").title()} is required'}
            
            # Validate email format
            if not self.validate_email(user_data['email']):
                return {'success': False, 'message': 'Invalid email format'}
            
            # Validate phone number
            if not self.validate_phone(user_data['phone']):
                return {'success': False, 'message': 'Invalid phone number format'}
            
            # Validate GST number (now required)
            if not self.validate_gst_number(user_data['gst_number']):
                return {'success': False, 'message': 'Invalid GST number format'}
            
            # Validate password strength
            if len(user_data['password']) < 6:
                return {'success': False, 'message': 'Password must be at least 6 characters long'}
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute('SELECT id FROM users WHERE email = ?', (user_data['email'].lower(),))
            if cursor.fetchone():
                conn.close()
                return {'success': False, 'message': 'Email already registered'}
            
            # Hash password
            password_hash, salt = self.hash_password(user_data['password'])
            
            # Insert new user with current IST time as last_login
            cursor.execute('''
                INSERT INTO users (first_name, last_name, email, phone, company, gst_number, password_hash, salt, last_login)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+5 hours', '+30 minutes'))
            ''', (
                user_data['first_name'].strip(),
                user_data['last_name'].strip(),
                user_data['email'].lower().strip(),
                user_data['phone'].strip(),
                user_data['company'].strip(),
                user_data.get('gst_number', '').upper().strip() if user_data.get('gst_number') else None,
                password_hash,
                salt
            ))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return {
                'success': True, 
                'message': 'User registered successfully',
                'user_id': user_id
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Registration error: {str(e)}'}
    
    def authenticate_user(self, email, password):
        """Authenticate user login"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get user data
            cursor.execute('''
                SELECT id, first_name, last_name, email, phone, company, gst_number, 
                       password_hash, salt, is_active, created_at, last_login
                FROM users WHERE email = ?
            ''', (email.lower(),))
            
            user_data = cursor.fetchone()
            if not user_data:
                conn.close()
                return {'success': False, 'message': 'Invalid email or password'}
            
            user_id, first_name, last_name, email, phone, company, gst_number, stored_hash, salt, is_active, created_at, last_login = user_data
            
            if not is_active:
                conn.close()
                return {'success': False, 'message': 'Account is deactivated'}
            
            # Verify password
            password_hash, _ = self.hash_password(password, salt)
            if password_hash != stored_hash:
                conn.close()
                return {'success': False, 'message': 'Invalid email or password'}
            
            # Update last login with IST time
            cursor.execute("UPDATE users SET last_login = datetime('now', '+5 hours', '+30 minutes') WHERE id = ?", (user_id,))
            conn.commit()
            conn.close()
            
            # Create session token
            session_token = self.create_session(user_id)
            
            return {
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user_id,
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'phone': phone,
                    'company': company,
                    'gst_number': gst_number,
                    'created_at': created_at,
                    'last_login': last_login
                },
                'session_token': session_token
            }
            
        except Exception as e:
            return {'success': False, 'message': f'Authentication error: {str(e)}'}
    
    def create_session(self, user_id):
        """Create a new session for user"""
        try:
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(days=30)  # 30-day session
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Deactivate old sessions
            cursor.execute('UPDATE sessions SET is_active = 0 WHERE user_id = ?', (user_id,))
            
            # Create new session
            cursor.execute('''
                INSERT INTO sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, session_token, expires_at))
            
            conn.commit()
            conn.close()
            
            return session_token
            
        except Exception as e:
            print(f"Session creation error: {e}")
            return None
    
    def validate_session(self, session_token):
        """Validate session token and return user data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT u.id, u.first_name, u.last_name, u.email, u.phone, 
                       u.company, u.gst_number, u.created_at, u.last_login, s.expires_at
                FROM users u
                JOIN sessions s ON u.id = s.user_id
                WHERE s.session_token = ? AND s.is_active = 1 AND s.expires_at > CURRENT_TIMESTAMP
            ''', (session_token,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                user_id, first_name, last_name, email, phone, company, gst_number, created_at, last_login, expires_at = result
                return {
                    'valid': True,
                    'user': {
                        'id': user_id,
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'phone': phone,
                        'company': company,
                        'gst_number': gst_number,
                        'created_at': created_at,
                        'last_login': last_login
                    }
                }
            else:
                return {'valid': False}
                
        except Exception as e:
            print(f"Session validation error: {e}")
            return {'valid': False}
    
    def logout_user(self, session_token):
        """Logout user by deactivating session"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('UPDATE sessions SET is_active = 0 WHERE session_token = ?', (session_token,))
            conn.commit()
            conn.close()
            
            return {'success': True, 'message': 'Logged out successfully'}
            
        except Exception as e:
            return {'success': False, 'message': f'Logout error: {str(e)}'}
    
    def get_user_preferences(self, user_id):
        """Get user preferences"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT preference_key, preference_value
                FROM user_preferences WHERE user_id = ?
            ''', (user_id,))
            
            preferences = {}
            for row in cursor.fetchall():
                key, value = row
                try:
                    preferences[key] = json.loads(value)
                except:
                    preferences[key] = value
            
            conn.close()
            return preferences
            
        except Exception as e:
            print(f"Error getting preferences: {e}")
            return {}
    
    def set_user_preference(self, user_id, key, value):
        """Set user preference"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Convert value to JSON string if it's not a string
            if not isinstance(value, str):
                value = json.dumps(value)
            
            cursor.execute('''
                INSERT OR REPLACE INTO user_preferences (user_id, preference_key, preference_value, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_id, key, value))
            
            conn.commit()
            conn.close()
            
            return {'success': True}
            
        except Exception as e:
            return {'success': False, 'message': f'Error setting preference: {str(e)}'}
    
    def update_user_profile(self, user_id, update_data):
        """Update user profile information"""
        try:
            # Define allowed fields for update (GST number excluded)
            allowed_fields = ['first_name', 'last_name', 'phone', 'company']
            update_fields = []
            update_values = []
            
            for field, value in update_data.items():
                if field in allowed_fields and value is not None:
                    if field == 'phone' and not self.validate_phone(value):
                        return {'success': False, 'message': 'Invalid phone number format'}
                    
                    update_fields.append(f'{field} = ?')
                    update_values.append(value.strip() if isinstance(value, str) else value)
            
            if not update_fields:
                return {'success': False, 'message': 'No valid fields to update'}
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
            update_values.append(user_id)
            
            cursor.execute(query, update_values)
            
            if cursor.rowcount == 0:
                conn.close()
                return {'success': False, 'message': 'User not found'}
            
            conn.commit()
            conn.close()
            
            return {'success': True, 'message': 'Profile updated successfully'}
                
        except Exception as e:
            return {'success': False, 'message': f'Error updating profile: {str(e)}'}
    
    def change_user_password(self, user_id, password_data):
        """Change user password"""
        try:
            current_password = password_data.get('current_password')
            new_password = password_data.get('new_password')
            
            if not current_password or not new_password:
                return {'success': False, 'message': 'Current and new passwords are required'}
            
            if len(new_password) < 6:
                return {'success': False, 'message': 'New password must be at least 6 characters long'}
            
            # Get current user data
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT password_hash, salt FROM users WHERE id = ?', (user_id,))
            user_data = cursor.fetchone()
            
            if not user_data:
                conn.close()
                return {'success': False, 'message': 'User not found'}
            
            stored_hash, salt = user_data
            
            # Verify current password
            current_hash = hashlib.sha256((current_password + salt).encode()).hexdigest()
            if current_hash != stored_hash:
                conn.close()
                return {'success': False, 'message': 'Current password is incorrect'}
            
            # Generate new password hash
            new_salt = secrets.token_hex(16)
            new_hash = hashlib.sha256((new_password + new_salt).encode()).hexdigest()
            
            # Update password
            cursor.execute('''
                UPDATE users 
                SET password_hash = ?, salt = ?
                WHERE id = ?
            ''', (new_hash, new_salt, user_id))
            
            conn.commit()
            conn.close()
            
            return {'success': True, 'message': 'Password changed successfully'}
            
        except Exception as e:
            return {'success': False, 'message': f'Error changing password: {str(e)}'}

# Authentication decorator for Flask routes
def require_auth(auth_backend):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            session_token = request.headers.get('Authorization')
            if session_token and session_token.startswith('Bearer '):
                session_token = session_token[7:]  # Remove 'Bearer ' prefix
                
                session_data = auth_backend.validate_session(session_token)
                if session_data['valid']:
                    request.current_user = session_data['user']
                    return f(*args, **kwargs)
            
            return {'success': False, 'message': 'Authentication required'}, 401
        return decorated_function
    return decorator

if __name__ == '__main__':
    # Test the authentication system
    auth = AuthBackend()
    
    # Test user registration
    test_user = {
        'first_name': 'Test',
        'last_name': 'User',
        'email': 'test@example.com',
        'phone': '9876543210',
        'company': 'Test Company',
        'gst_number': '27AACCF6368D1CX',
        'password': 'testpass123'
    }
    
    print("Testing user registration...")
    result = auth.register_user(test_user)
    print(f"Registration result: {result}")
    
    if result['success']:
        print("\nTesting user authentication...")
        auth_result = auth.authenticate_user('test@example.com', 'testpass123')
        print(f"Authentication result: {auth_result}")
        
        if auth_result['success']:
            session_token = auth_result['session_token']
            print(f"\nSession token: {session_token}")
            
            print("\nTesting session validation...")
            session_check = auth.validate_session(session_token)
            print(f"Session validation: {session_check}")
