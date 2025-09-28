#!/usr/bin/env python3
"""
Simple HTTP server for GST Report Generator
Run this script to serve the web application locally
"""

import http.server
import socketserver
import os
import json
import urllib.parse
from pathlib import Path
from auth_backend import AuthBackend
import hmac
import hashlib

PORT = int(os.environ.get('PORT', '8083'))

class AuthHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.auth_backend = AuthBackend()
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/api/auth/profile':
            self.handle_get_profile()
        elif self.path == '/' or self.path == '':
            # Serve index.html for root path
            self.path = '/index.html'
            super().do_GET()
        else:
            super().do_GET()
    
    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()
    
    def do_OPTIONS(self):
        """Handle preflight CORS requests"""
        self.send_response(200)
        self.end_headers()
    
    def do_POST(self):
        """Handle POST requests for authentication endpoints"""
        if self.path == '/api/auth/register':
            self.handle_register()
        elif self.path == '/api/auth/login':
            self.handle_login()
        elif self.path == '/api/auth/logout':
            self.handle_logout()
        elif self.path == '/api/auth/validate':
            self.handle_validate_session()
        elif self.path == '/api/auth/change-password':
            self.handle_change_password()
        elif self.path == '/api/payments/create-order':
            self.handle_create_order()
        elif self.path == '/api/payments/verify':
            self.handle_verify_payment()
        else:
            super().do_POST()
    
    def do_PUT(self):
        """Handle PUT requests for profile updates"""
        if self.path == '/api/auth/profile':
            self.handle_update_profile()
        else:
            self.send_error(404, "Not Found")
    
    def handle_register(self):
        """Handle user registration"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            user_data = json.loads(post_data.decode('utf-8'))
            
            result = self.auth_backend.register_user(user_data)
            
            self.send_response(200 if result['success'] else 400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        except Exception as e:
            self.send_error_response(500, 'Registration error: ' + str(e))
    
    def handle_login(self):
        """Handle user login"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            login_data = json.loads(post_data.decode('utf-8'))
            
            result = self.auth_backend.authenticate_user(
                login_data.get('email', ''),
                login_data.get('password', '')
            )
            
            self.send_response(200 if result['success'] else 401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        except Exception as e:
            self.send_error_response(500, 'Login error: ' + str(e))
    
    def handle_logout(self):
        """Handle user logout"""
        try:
            auth_header = self.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                session_token = auth_header[7:]
                result = self.auth_backend.logout_user(session_token)
            else:
                result = {'success': False, 'message': 'No session token provided'}
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        except Exception as e:
            self.send_error_response(500, 'Logout error: ' + str(e))
    
    def handle_validate_session(self):
        """Handle session validation"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            session_token = data.get('session_token', '')
            result = self.auth_backend.validate_session(session_token)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        except Exception as e:
            self.send_error_response(500, 'Validation error: ' + str(e))
    
    def handle_get_profile(self):
        """Handle get user profile"""
        try:
            auth_header = self.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                session_token = auth_header[7:]
                session_data = self.auth_backend.validate_session(session_token)
                
                if session_data['valid']:
                    user_id = session_data['user']['id']
                    preferences = self.auth_backend.get_user_preferences(user_id)
                    
                    result = {
                        'success': True,
                        'user': session_data['user'],
                        'preferences': preferences
                    }
                else:
                    result = {'success': False, 'message': 'Invalid session'}
            else:
                result = {'success': False, 'message': 'No session token provided'}
            
            self.send_response(200 if result['success'] else 401)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        except Exception as e:
            self.send_error_response(500, 'Profile error: ' + str(e))
    
    def handle_update_profile(self):
        """Handle profile update"""
        try:
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_error_response(401, 'No session token provided')
                return
                
            session_token = auth_header[7:]
            session_data = self.auth_backend.validate_session(session_token)
            
            if not session_data['valid']:
                self.send_error_response(401, 'Invalid session')
                return
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            update_data = json.loads(post_data.decode('utf-8'))
            
            user_id = session_data['user']['id']
            result = self.auth_backend.update_user_profile(user_id, update_data)
            
            self.send_response(200 if result['success'] else 400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        except Exception as e:
            self.send_error_response(500, 'Profile update error: ' + str(e))
    
    def handle_change_password(self):
        """Handle password change"""
        try:
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                self.send_error_response(401, 'No session token provided')
                return
                
            session_token = auth_header[7:]
            session_data = self.auth_backend.validate_session(session_token)
            
            if not session_data['valid']:
                self.send_error_response(401, 'Invalid session')
                return
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            password_data = json.loads(post_data.decode('utf-8'))
            
            user_id = session_data['user']['id']
            result = self.auth_backend.change_user_password(user_id, password_data)
            
            self.send_response(200 if result['success'] else 400)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        except Exception as e:
            self.send_error_response(500, 'Password change error: ' + str(e))

    # ---------------- Razorpay Secure Flow ----------------
    def load_razorpay_credentials(self):
        # Prefer environment variables in production (Cloud Run)
        key_id = os.environ.get('RAZORPAY_KEY_ID')
        key_secret = os.environ.get('RAZORPAY_KEY_SECRET')
        if key_id and key_secret:
            return key_id, key_secret
        # Fallback to local file for local development
        try:
            cfg_path = Path(__file__).parent / 'razorpay.local.json'
            data = json.loads(cfg_path.read_text())
            return data.get('key_id'), data.get('key_secret')
        except Exception:
            return None, None

    def handle_create_order(self):
        try:
            key_id, key_secret = self.load_razorpay_credentials()
            if not key_id or not key_secret:
                self.send_error_response(500, 'Razorpay credentials not configured')
                return

            content_length = int(self.headers.get('Content-Length', '0') or 0)
            body = self.rfile.read(content_length) if content_length else b'{}'
            data = json.loads(body.decode('utf-8')) if body else {}
            amount = int(data.get('amount', 1200 * 100))
            currency = data.get('currency', 'INR')
            receipt = data.get('receipt', 'order_rcpt_1')

            # Create order via Razorpay REST API
            import urllib.request
            req = urllib.request.Request('https://api.razorpay.com/v1/orders', method='POST')
            req.add_header('Content-Type', 'application/json')
            # Basic auth with key_id:key_secret
            import base64
            token = base64.b64encode(f"{key_id}:{key_secret}".encode()).decode()
            req.add_header('Authorization', f'Basic {token}')
            payload = json.dumps({
                'amount': amount,
                'currency': currency,
                'receipt': receipt
            }).encode()
            with urllib.request.urlopen(req, payload) as resp:
                resp_data = resp.read().decode('utf-8')
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(resp_data.encode('utf-8'))
        except Exception as e:
            self.send_error_response(500, 'Create order error: ' + str(e))

    def handle_verify_payment(self):
        try:
            key_id, key_secret = self.load_razorpay_credentials()
            if not key_id or not key_secret:
                self.send_error_response(500, 'Razorpay credentials not configured')
                return

            content_length = int(self.headers.get('Content-Length', '0') or 0)
            body = self.rfile.read(content_length) if content_length else b'{}'
            data = json.loads(body.decode('utf-8'))

            order_id = data.get('razorpay_order_id')
            payment_id = data.get('razorpay_payment_id')
            signature = data.get('razorpay_signature')

            if not (order_id and payment_id and signature):
                self.send_error_response(400, 'Missing payment verification fields')
                return

            # Compute expected signature
            payload = f"{order_id}|{payment_id}".encode('utf-8')
            expected = hmac.new(key_secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
            verified = hmac.compare_digest(expected, signature)

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({ 'success': True, 'verified': bool(verified) }).encode('utf-8'))
        except Exception as e:
            self.send_error_response(500, 'Verify error: ' + str(e))
    
    def send_error_response(self, status_code, message):
        """Send error response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        error_response = {'success': False, 'message': message}
        self.wfile.write(json.dumps(error_response).encode('utf-8'))

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    with socketserver.TCPServer(("", PORT), AuthHTTPRequestHandler) as httpd:
        print("GST Report Generator with Authentication running at http://localhost:" + str(PORT))
        print("Authentication endpoints available:")
        print("  POST /api/auth/register - User registration")
        print("  POST /api/auth/login - User login")
        print("  POST /api/auth/logout - User logout")
        print("  POST /api/auth/validate - Session validation")
        print("  GET /api/auth/profile - Get user profile")
        httpd.serve_forever()
