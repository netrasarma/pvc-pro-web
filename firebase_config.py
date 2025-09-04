import firebase_admin
from firebase_admin import credentials, firestore, auth
import pyrebase
import hashlib
import uuid
import datetime
import platform
import os
import json

# Get Firebase configuration from environment variables (set by secret manager)
def get_firebase_config():
    """Get Firebase configuration from environment variables"""
    try:
        # Try to get from environment variables first (for production)
        api_key = os.getenv('FIREBASE_API_KEY')
        auth_domain = os.getenv('FIREBASE_AUTH_DOMAIN')
        project_id = os.getenv('FIREBASE_PROJECT_ID')
        storage_bucket = os.getenv('FIREBASE_STORAGE_BUCKET')
        messaging_sender_id = os.getenv('FIREBASE_MESSAGING_SENDER_ID')
        app_id = os.getenv('FIREBASE_APP_ID')

        if all([api_key, auth_domain, project_id, storage_bucket, messaging_sender_id, app_id]):
            return {
                "apiKey": api_key,
                "authDomain": auth_domain,
                "databaseURL": f"https://{project_id}-default-rtdb.firebaseio.com",
                "projectId": project_id,
                "storageBucket": storage_bucket,
                "messagingSenderId": messaging_sender_id,
                "appId": app_id
            }
        else:
            # Fallback to hardcoded config for development (should be removed in production)
            print("Warning: Using fallback Firebase config. Environment variables not set.")
            return {
                "apiKey": "AIzaSyBSUk5IGYsEckBkSgiexQvDCUvo6IsIe2w",
                "authDomain": "pvc-pro-web.firebaseapp.com",
                "databaseURL": "https://pvc-pro-web-default-rtdb.firebaseio.com",
                "projectId": "pvc-pro-web",
                "storageBucket": "pvc-pro-web.firebasestorage.app",
                "messagingSenderId": "432888002709",
                "appId": "1:432888002709:web:06951cd41559f17f42039c"
            }
    except Exception as e:
        print(f"Error getting Firebase config: {e}")
        # Fallback config
        return {
            "apiKey": "AIzaSyBSUk5IGYsEckBkSgiexQvDCUvo6IsIe2w",
            "authDomain": "pvc-pro-web.firebaseapp.com",
            "databaseURL": "https://pvc-pro-web-default-rtdb.firebaseio.com",
            "projectId": "pvc-pro-web",
            "storageBucket": "pvc-pro-web.firebasestorage.app",
            "messagingSenderId": "432888002709",
            "appId": "1:432888002709:web:06951cd41559f17f42039c"
        }

# Get Firebase service account key from environment variable or secret manager
def get_firebase_service_account():
    """Get Firebase service account key from environment or secret manager only"""
    try:
        # Try to get from environment variable first
        service_account_json = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON')
        if service_account_json:
            print("Loading Firebase service account from environment variable.")
            return json.loads(service_account_json)

        # Try to get from secret manager (Google Cloud)
        try:
            from google.cloud import secretmanager_v1
            client = secretmanager_v1.SecretManagerServiceClient()
            project_id = os.getenv('GOOGLE_CLOUD_PROJECT', 'pvc-pro-web')
            secret_name = 'firebase-service-account'
            version = 'latest'

            name = f"projects/{project_id}/secrets/{secret_name}/versions/{version}"
            response = client.access_secret_version(request={"name": name})
            service_account_json = response.payload.data.decode("UTF-8")
            print("Loading Firebase service account from Google Cloud Secret Manager.")
            return json.loads(service_account_json)
        except Exception as e:
            print(f"Could not get Firebase service account from secret manager: {e}")

        print("Error: No Firebase service account found. Please set FIREBASE_SERVICE_ACCOUNT_JSON environment variable or ensure firebase-service-account secret exists in Google Cloud Secret Manager.")
        return None

    except Exception as e:
        print(f"Error getting Firebase service account: {e}")
        return None

# Initialize Firebase configuration
FIREBASE_CONFIG = get_firebase_config()

class FirebaseManager:
    def __init__(self):
        import json
        self.firebase_admin_initialized = False
        try:
            if not firebase_admin._apps: # Check if any app is already initialized
                # Get service account credentials from environment/secret manager
                service_account_data = get_firebase_service_account()
                if service_account_data:
                    cred = credentials.Certificate(service_account_data)
                    firebase_admin.initialize_app(cred)
                    self.firebase_admin_initialized = True
                    print("Firebase Admin SDK initialized successfully using secure credentials.")
                else:
                    print("Error: Could not load Firebase service account credentials.")
                    print("Please ensure FIREBASE_SERVICE_ACCOUNT_JSON environment variable is set or firebase-service-account secret exists in Google Cloud Secret Manager.")
                    return
            else:
                self.firebase_admin_initialized = True
                print("Firebase Admin SDK already initialized.")
        except ValueError as e:
            # This error occurs if initialize_app is called again without a name
            # and an app is already initialized. We can ignore it if it's
            # due to a legitimate second initialization attempt.
            if "The default Firebase app already exists" not in str(e):
                print(f"Error initializing Firebase Admin SDK: {e}")
                print("Please check your Firebase service account credentials.")
        except Exception as e:
            print(f"Error initializing Firebase Admin SDK: {e}")
            print("Please check your Firebase service account credentials and ensure they are properly configured.")
 
        try:
            self.pb = pyrebase.initialize_app(FIREBASE_CONFIG)
            self.auth = self.pb.auth()
            self.db = firestore.client()
            
            self.users_collection = self.db.collection('users')
            self.devices_collection = self.db.collection('devices')
            self.sessions_collection = self.db.collection('sessions')
            self.activation_keys_collection = self.db.collection('activation_keys')
            self.security_logs_collection = self.db.collection('security_logs')
            self.admin_actions_collection = self.db.collection('admin_actions')
            
            self.max_devices_per_user = 2
            self.max_login_attempts = 5
            self.session_timeout_hours = 24

            import platform
            import hashlib
            import uuid

        except Exception as e:
            print(f"Error initializing Pyrebase: {e}")
            print("Please check your Firebase configuration")
            return

    def _check_login_attempts(self, email):
        """Check if user has exceeded login attempts"""
        if not self.firebase_admin_initialized:
            print("Firebase Admin SDK not initialized. Cannot check login attempts.")
            return False
        try:
            import datetime
            one_hour_ago = datetime.datetime.now() - datetime.timedelta(hours=1)

            failed_attempts = self.security_logs_collection.where(
                'event_type', '==', 'failed_login'
            ).where(
                'details.email', '==', email
            ).where(
                'timestamp', '>=', one_hour_ago
            ).get()

            return len(failed_attempts) >= self.max_login_attempts
        except Exception as e:
            print(f"Error checking login attempts for {email}: {e}")
            return False
            
            
            # Create fingerprint from system info
            fingerprint_string = ''.join(str(v) for v in system_info.values())
            return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
        except Exception:
            # Fallback to UUID if system info fails
            return str(uuid.uuid4())[:16]

    def create_user(self, email, password, user_data):
        """Create a new user with Firebase Authentication and Firestore profile"""
        try:
            # Create auth user
            user = auth.create_user(
                email=email,
                password=password
            )
            
            # Create user profile in Firestore
            user_ref = self.db.collection('users').document(user.uid)
            user_data['uid'] = user.uid
            user_data['email'] = email
            user_data['is_activated'] = False
            user_data['status'] = 'Registered'
            user_ref.set(user_data)
            
            return True, user.uid
        except Exception as e:
            return False, str(e)

    def sign_in(self, email, password, device_id=None):
        """Sign in user with email, password and no security checks"""
        try:
            print(f"Attempting sign in for email: {email}")
            # Authenticate the user directly without security checks
            try:
                user = self.auth.sign_in_with_email_and_password(email, password)
                uid = user['localId']
            except Exception as auth_error:
                print(f"Authentication error for email {email}: {auth_error}")
                return False, "Invalid email or password"
            
            # Return user info directly
            return True, user
            
        except Exception as e:
            print(f"Login error for email {email}: {e}")
            return False, str(e)
            
    def _clear_old_sessions(self, uid):
        """Clear old sessions for user"""
        old_sessions = self.sessions_collection.where('user_id', '==', uid).get()
        for session in old_sessions:
            session.reference.delete()
            
    def _create_new_session(self, uid, device_id):
        """Create a new session"""
        import uuid
        session_token = str(uuid.uuid4())
        self.sessions_collection.add({
            'user_id': uid,
            'device_id': device_id,
            'session_token': session_token,
            'created_at': firestore.SERVER_TIMESTAMP,
            'last_active': firestore.SERVER_TIMESTAMP
        })
        return session_token

    def get_user_profile(self, uid):
        """Get user profile from Firestore with security checks"""
        try:
            doc = self.users_collection.document(uid).get()
            if not doc.exists:
                return False, "User profile not found"
                
            user_data = doc.to_dict()
            
            # Check if user is locked
            if user_data.get('is_locked', False):
                return False, "Account is locked. Please contact administrator."
                
            # Verify subscription expiry using server time
            if user_data.get('expires_on'):
                server_time = self.db.collection('utility').document('server_time').get()
                if server_time.exists:
                    current_time = server_time.to_dict().get('timestamp')
                    expiry = datetime.datetime.strptime(user_data['expires_on'], "%Y-%m-%d")
                    if current_time > expiry:
                        return False, "Subscription expired"
            
            return True, user_data
        except Exception as e:
            return False, str(e)

    def update_user_profile(self, uid, data):
        """Update user profile in Firestore with security checks"""
        try:
            # Don't allow updating sensitive fields
            protected_fields = ['is_admin', 'is_locked', 'activation_key', 'subscription_end']
            for field in protected_fields:
                if field in data:
                    del data[field]
                    
            self.users_collection.document(uid).update(data)
            return True, "Profile updated successfully"
        except Exception as e:
            return False, str(e)
            
    def lock_user(self, uid, reason=""):
        """Lock a user account (Admin only)"""
        try:
            self.users_collection.document(uid).update({
                'is_locked': True,
                'lock_reason': reason,
                'locked_at': firestore.SERVER_TIMESTAMP
            })
            return True, "User account locked"
        except Exception as e:
            return False, str(e)
            
    def unlock_user(self, uid):
        """Unlock a user account (Admin only)"""
        try:
            self.users_collection.document(uid).update({
                'is_locked': False,
                'lock_reason': '',
                'locked_at': None
            })
            return True, "User account unlocked"
        except Exception as e:
            return False, str(e)
            
    def disable_device(self, device_id):
        """Disable a device (Admin only)"""
        try:
            device_docs = self.devices_collection.where('device_id', '==', device_id).get()
            for doc in device_docs:
                doc.reference.update({
                    'is_active': False,
                    'disabled_at': firestore.SERVER_TIMESTAMP
                })
            return True, "Device disabled"
        except Exception as e:
            return False, str(e)
            
    def _verify_system_integrity(self):
        """Verify integrity of critical system files"""
        try:
            for file_path, expected_hash in self.file_integrity_hashes.items():
                if os.path.exists(file_path):
                    current_hash = self._calculate_file_hash(file_path)
                    if current_hash != expected_hash:
                        self._log_security_event('file_integrity_violation', details={'file': file_path})
                        return False
                else:
                    self._log_security_event('file_missing', details={'file': file_path})
                    return False
            return True
        except Exception:
            return False
            
    def verify_file_integrity(self, file_path, expected_hash):
        """Verify file integrity using hash"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            return file_hash == expected_hash
        except Exception:
            return False
            
    def validate_session(self, session_token, user_id):
        """Validate user session token"""
        try:
            session_query = self.sessions_collection.where(
                'session_token', '==', session_token
            ).where(
                'user_id', '==', user_id
            ).limit(1).get()
            
            if not session_query:
                return False, "Invalid session"
                
            session_data = session_query[0].to_dict()
            
            # Check session timeout
            created_at = session_data.get('created_at')
            if created_at:
                session_age = datetime.datetime.now() - created_at
                if session_age.total_seconds() > (self.session_timeout_hours * 3600):
                    # Delete expired session
                    session_query[0].reference.delete()
                    return False, "Session expired"
            
            # Update last active
            session_query[0].reference.update({
                'last_active': firestore.SERVER_TIMESTAMP
            })
            
            return True, "Session valid"
        except Exception as e:
            return False, str(e)
            
    def get_user_devices(self, user_id):
        """Get all devices for a user (Admin only)"""
        try:
            devices = self.devices_collection.where('user_id', '==', user_id).get()
            device_list = []
            for device in devices:
                device_data = device.to_dict()
                device_data['id'] = device.id
                device_list.append(device_data)
            return True, device_list
        except Exception as e:
            return False, str(e)
            
    def get_security_logs(self, limit=100, event_type=None):
        """Get security logs (Admin only)"""
        try:
            query = self.security_logs_collection.order_by('timestamp', direction=firestore.Query.DESCENDING).limit(limit)
            
            if event_type:
                query = query.where('event_type', '==', event_type)
                
            logs = query.get()
            log_list = []
            for log in logs:
                log_data = log.to_dict()
                log_data['id'] = log.id
                log_list.append(log_data)
            return True, log_list
        except Exception as e:
            return False, str(e)
            
    def disable_software_remotely(self, reason=""):
        """Disable software remotely (Master Admin only)"""
        try:
            # Create a global disable flag
            disable_doc = self.db.collection('system_control').document('software_status')
            disable_doc.set({
                'is_disabled': True,
                'disabled_at': firestore.SERVER_TIMESTAMP,
                'reason': reason,
                'disabled_by': 'master_admin'
            })
            
            # Log the action
            self._log_security_event('software_disabled', details={'reason': reason})
            
            return True, "Software disabled remotely"
        except Exception as e:
            return False, str(e)
            
    def enable_software_remotely(self):
        """Enable software remotely (Master Admin only)"""
        try:
            # Remove the global disable flag
            disable_doc = self.db.collection('system_control').document('software_status')
            disable_doc.set({
                'is_disabled': False,
                'enabled_at': firestore.SERVER_TIMESTAMP,
                'enabled_by': 'master_admin'
            })
            
            # Log the action
            self._log_security_event('software_enabled')
            
            return True, "Software enabled remotely"
        except Exception as e:
            return False, str(e)
            
    def check_software_status(self):
        """Check if software is remotely disabled"""
        try:
            status_doc = self.db.collection('system_control').document('software_status').get()
            if status_doc.exists:
                status_data = status_doc.to_dict()
                if status_data.get('is_disabled', False):
                    return False, status_data.get('reason', 'Software disabled by administrator')
            return True, "Software enabled"
        except Exception:
            return True, "Software enabled"  # Default to enabled if check fails
            
    def log_admin_action(self, admin_id, action, target_user=None, details=None):
        """Log admin actions for audit trail"""
        try:
            action_entry = {
                'admin_id': admin_id,
                'action': action,
                'target_user': target_user,
                'details': details or {},
                'timestamp': firestore.SERVER_TIMESTAMP,
                'device_fingerprint': self._get_device_fingerprint()
            }
            self.admin_actions_collection.add(action_entry)
            return True, "Action logged"
        except Exception as e:
            return False, str(e)

    def validate_activation_key(self, key):
        """Validate activation key from Firestore"""
        try:
            key_ref = self.db.collection('activation_keys').document(key)
            key_doc = key_ref.get()
            
            if not key_doc.exists:
                return False, "Invalid activation key"
                
            key_data = key_doc.to_dict()
            if key_data.get('status') == 'USED':
                return False, "Key already used"
                
            return True, key_data
        except Exception as e:
            return False, str(e)

    def activate_user(self, uid, key):
        """Activate user subscription with key"""
        try:
            # Update key status
            key_ref = self.db.collection('activation_keys').document(key)
            key_ref.update({
                'status': 'USED',
                'used_by': uid,
                'used_date': firestore.SERVER_TIMESTAMP
            })
            
            # Update user status
            import datetime
            now = datetime.datetime.now()
            expiry = now + datetime.timedelta(days=365)
            
            user_ref = self.db.collection('users').document(uid)
            user_ref.update({
                'is_activated': True,
                'status': 'Active',
                'activation_key': key,
                'activation_date': now,
                'subscription_start': now,
                'subscription_end': expiry,
                'expires_on': expiry.strftime("%Y-%m-%d")
            })
            
            return True, "User activated successfully"
        except Exception as e:
            return False, str(e)

    # ==================== CREDIT MANAGEMENT SYSTEM ====================
    
    def create_payment_request(self, uid, credits, amount, payment_method='UPI'):
        """Create a payment request for credit purchase"""
        try:
            import uuid
            payment_id = f"PVC{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}{str(uuid.uuid4())[:4].upper()}"
            
            payment_data = {
                'payment_id': payment_id,
                'user_id': uid,
                'credits': int(credits),
                'amount': float(amount),
                'payment_method': payment_method,
                'status': 'PENDING',
                'created_at': firestore.SERVER_TIMESTAMP,
                'expires_at': datetime.datetime.now() + datetime.timedelta(hours=1),  # 1 hour expiry
                'upi_id': 'officialnetrasarma@paytm',  # Your UPI ID
                'merchant_name': 'PDF Cropper Pro',
                'transaction_note': f'Credit Purchase - {credits} Credits'
            }
            
            # Store payment request
            payment_ref = self.db.collection('payment_requests').document(payment_id)
            payment_ref.set(payment_data)
            
            # Log payment request
            self._log_security_event('payment_request_created', user_id=uid, details={
                'payment_id': payment_id,
                'credits': credits,
                'amount': amount
            })
            
            return True, payment_data
        except Exception as e:
            return False, str(e)
    
    def verify_payment_status(self, payment_id):
        """Verify payment status (to be integrated with payment gateway webhook)"""
        try:
            payment_ref = self.db.collection('payment_requests').document(payment_id)
            payment_doc = payment_ref.get()
            
            if not payment_doc.exists:
                return False, "Payment request not found"
            
            payment_data = payment_doc.to_dict()
            
            # Check if payment has expired
            if payment_data.get('expires_at') and payment_data['expires_at'] < datetime.datetime.now():
                payment_ref.update({
                    'status': 'EXPIRED',
                    'updated_at': firestore.SERVER_TIMESTAMP
                })
                return False, "Payment request expired"
            
            return True, payment_data
        except Exception as e:
            return False, str(e)
    
    def confirm_payment(self, payment_id, transaction_id=None, payment_gateway_response=None):
        """Confirm payment and add credits to user account"""
        try:
            payment_ref = self.db.collection('payment_requests').document(payment_id)
            payment_doc = payment_ref.get()
            
            if not payment_doc.exists:
                return False, "Payment request not found"
            
            payment_data = payment_doc.to_dict()
            
            if payment_data.get('status') != 'PENDING':
                return False, f"Payment already {payment_data.get('status').lower()}"
            
            # Calculate bonus credits
            credits = payment_data['credits']
            bonus_credits = 0
            if credits >= 1000:
                bonus_credits = 200
            elif credits >= 500:
                bonus_credits = 75
            elif credits >= 250:
                bonus_credits = 25
            
            total_credits = credits + bonus_credits
            
            # Update payment status
            payment_ref.update({
                'status': 'COMPLETED',
                'transaction_id': transaction_id,
                'payment_gateway_response': payment_gateway_response,
                'bonus_credits': bonus_credits,
                'total_credits': total_credits,
                'completed_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            
            # Add credits to user account
            user_id = payment_data['user_id']
            success, result = self.add_user_credits(user_id, total_credits)
            
            if not success:
                # Rollback payment status if credit addition fails
                payment_ref.update({
                    'status': 'FAILED',
                    'error': result,
                    'updated_at': firestore.SERVER_TIMESTAMP
                })
                return False, f"Failed to add credits: {result}"
            
            # Log successful payment
            self._log_security_event('payment_completed', user_id=user_id, details={
                'payment_id': payment_id,
                'credits': credits,
                'bonus_credits': bonus_credits,
                'total_credits': total_credits,
                'amount': payment_data['amount'],
                'transaction_id': transaction_id
            })
            
            return True, {
                'credits_added': total_credits,
                'bonus_credits': bonus_credits,
                'new_balance': result
            }
        except Exception as e:
            return False, str(e)
    
    def add_user_credits(self, uid, credits):
        """Add credits to user account"""
        try:
            user_ref = self.db.collection('users').document(uid)
            user_doc = user_ref.get()
            
            if not user_doc.exists:
                return False, "User not found"
            
            user_data = user_doc.to_dict()
            current_credits = user_data.get('credits', 0)
            new_balance = current_credits + credits
            
            # Update user credits
            user_ref.update({
                'credits': new_balance,
                'last_credit_update': firestore.SERVER_TIMESTAMP
            })
            
            # Log credit transaction
            self.db.collection('credit_transactions').add({
                'user_id': uid,
                'type': 'CREDIT',
                'amount': credits,
                'balance_before': current_credits,
                'balance_after': new_balance,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'description': f'Credits added: {credits}'
            })
            
            return True, new_balance
        except Exception as e:
            return False, str(e)
    
    def deduct_user_credit(self, uid, credits=1, description=None):
        """Deduct credits from user account"""
        try:
            user_ref = self.db.collection('users').document(uid)
            user_doc = user_ref.get()
            
            if not user_doc.exists:
                return False, "User not found"
            
            user_data = user_doc.to_dict()
            current_credits = user_data.get('credits', 0)
            
            if current_credits < credits:
                return False, "Insufficient credits"
            
            new_balance = current_credits - credits
            
            # Update user credits
            user_ref.update({
                'credits': new_balance,
                'last_credit_update': firestore.SERVER_TIMESTAMP
            })
            
            # Generate transaction ID
            import uuid
            transaction_id = f"TXN_{uuid.uuid4().hex[:8].upper()}"
            
            # Log credit transaction - store negative amount for debits
            self.db.collection('credit_transactions').add({
                'user_id': uid,
                'type': 'DEBIT',
                'amount': -credits,  # Negative amount for debits
                'balance_before': current_credits,
                'balance_after': new_balance,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'description': description or f'Credits deducted for document processing: {credits}',
                'transaction_id': transaction_id
            })
            
            return True, new_balance
        except Exception as e:
            return False, str(e)
    
    def get_user_credit_history(self, uid, limit=50):
        """Get user's credit transaction history"""
        try:
            transactions = self.db.collection('credit_transactions')\
                .where('user_id', '==', uid)\
                .order_by('timestamp', direction=firestore.Query.DESCENDING)\
                .limit(limit)\
                .get()
            
            transaction_list = []
            for transaction in transactions:
                transaction_data = transaction.to_dict()
                transaction_data['id'] = transaction.id
                transaction_list.append(transaction_data)
            
            return True, transaction_list
        except Exception as e:
            return False, str(e)
    
    def get_payment_history(self, uid=None, limit=50):
        """Get payment history (admin can see all, users see their own)"""
        try:
            query = self.db.collection('payment_requests')\
                .order_by('created_at', direction=firestore.Query.DESCENDING)\
                .limit(limit)
            
            if uid:
                query = query.where('user_id', '==', uid)
            
            payments = query.get()
            payment_list = []
            for payment in payments:
                payment_data = payment.to_dict()
                payment_data['id'] = payment.id
                payment_list.append(payment_data)
            
            return True, payment_list
        except Exception as e:
            return False, str(e)
    
    def cancel_payment_request(self, payment_id, reason="User cancelled"):
        """Cancel a pending payment request"""
        try:
            payment_ref = self.db.collection('payment_requests').document(payment_id)
            payment_doc = payment_ref.get()
            
            if not payment_doc.exists:
                return False, "Payment request not found"
            
            payment_data = payment_doc.to_dict()
            
            if payment_data.get('status') != 'PENDING':
                return False, f"Cannot cancel payment with status: {payment_data.get('status')}"
            
            # Update payment status
            payment_ref.update({
                'status': 'CANCELLED',
                'cancellation_reason': reason,
                'cancelled_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            
            # Log cancellation
            self._log_security_event('payment_cancelled', user_id=payment_data['user_id'], details={
                'payment_id': payment_id,
                'reason': reason
            })
            
            return True, "Payment request cancelled"
        except Exception as e:
            return False, str(e)
    
    def get_pending_payments(self, uid=None):
        """Get pending payment requests"""
        try:
            query = self.db.collection('payment_requests')\
                .where('status', '==', 'PENDING')\
                .order_by('created_at', direction=firestore.Query.DESCENDING)
            
            if uid:
                query = query.where('user_id', '==', uid)
            
            payments = query.get()
            payment_list = []
            for payment in payments:
                payment_data = payment.to_dict()
                payment_data['id'] = payment.id
                
                # Check if payment has expired
                if payment_data.get('expires_at') and payment_data['expires_at'] < datetime.datetime.now():
                    # Mark as expired
                    payment.reference.update({
                        'status': 'EXPIRED',
                        'updated_at': firestore.SERVER_TIMESTAMP
                    })
                else:
                    payment_list.append(payment_data)
            
            return True, payment_list
        except Exception as e:
            return False, str(e)
    
    def admin_add_credits(self, admin_id, target_uid, credits, reason="Admin credit adjustment"):
        """Admin function to manually add credits to user account"""
        try:
            # Log admin action
            self.log_admin_action(admin_id, 'add_credits', target_uid, {
                'credits': credits,
                'reason': reason
            })
            
            # Add credits
            success, result = self.add_user_credits(target_uid, credits)
            
            if success:
                # Log the transaction with admin details
                self.db.collection('credit_transactions').add({
                    'user_id': target_uid,
                    'type': 'ADMIN_CREDIT',
                    'amount': credits,
                    'balance_after': result,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'description': f'Admin credit adjustment: {reason}',
                    'admin_id': admin_id
                })
            
            return success, result
        except Exception as e:
            return False, str(e)
    
    def admin_deduct_credits(self, admin_id, target_uid, credits, reason="Admin credit adjustment"):
        """Admin function to manually deduct credits from user account"""
        try:
            # Log admin action
            self.log_admin_action(admin_id, 'deduct_credits', target_uid, {
                'credits': credits,
                'reason': reason
            })
            
            # Deduct credits
            success, result = self.deduct_user_credit(target_uid, credits)
            
            if success:
                # Log the transaction with admin details
                self.db.collection('credit_transactions').add({
                    'user_id': target_uid,
                    'type': 'ADMIN_DEBIT',
                    'amount': credits,
                    'balance_after': result,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'description': f'Admin credit deduction: {reason}',
                    'admin_id': admin_id
                })
            
            return success, result
        except Exception as e:
            return False, str(e)

# Initialize Firebase manager
firebase = FirebaseManager()
