import firebase_admin
from firebase_admin import credentials, firestore, auth
import pyrebase
import hashlib
import uuid
import datetime
import platform
import os

# Firebase web app configuration
FIREBASE_CONFIG = {
    "apiKey": "AIzaSyBC7_ZtkquDPObGvmmHYDOCuzfSXANCBvY",
    "authDomain": "pvc-maker.firebaseapp.com",
    "databaseURL": "https://pvc-maker-default-rtdb.firebaseio.com",
    "projectId": "pvc-maker",
    "storageBucket": "pvc-maker.firebasestorage.app",
    "messagingSenderId": "818295298960",
    "appId": "1:818295298960:web:ea07cca1c740bf8988f115"
}

class FirebaseManager:
    def __init__(self):
        self.firebase_admin_initialized = False
        try:
            # Initialize Firebase Admin SDK using Application Default Credentials (ADC)
            firebase_admin.initialize_app()
            self.firebase_admin_initialized = True
            print("Firebase Admin SDK initialized successfully using Application Default Credentials (ADC).")
        except Exception as e:
            print(f"Error initializing Firebase Admin SDK with ADC: {e}")
            print("Ensure the Cloud Run service account has the necessary permissions.")
            return

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

        except Exception as e:
            print(f"Error initializing Pyrebase: {e}")
            print("Please check your Firebase configuration")
            return

    def _check_login_attempts(self, email):
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

    def _get_device_fingerprint(self):
        """Generate unique device fingerprint"""
        try:
            system_info = {
                'platform': platform.platform(),
                'processor': platform.processor(),
                'machine': platform.machine(),
                'node': platform.node(),
                'system': platform.system(),
                'release': platform.release()
            }
            fingerprint_string = ''.join(str(v) for v in system_info.values())
            return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
        except Exception:
            return str(uuid.uuid4())[:16]

    def create_user(self, email, password, user_data):
        """Create a new user with Firebase Authentication and Firestore profile"""
        try:
            user = auth.create_user(
                email=email,
                password=password
            )
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
        """Sign in user with email and password"""
        try:
            user = self.auth.sign_in_with_email_and_password(email, password)
            uid = user['localId']
            return True, user
        except Exception as e:
            return False, str(e)

    def get_user_profile(self, uid):
        """Get user profile from Firestore"""
        try:
            doc = self.users_collection.document(uid).get()
            if not doc.exists:
                return False, "User profile not found"
            user_data = doc.to_dict()
            if user_data.get('is_locked', False):
                return False, "Account is locked. Please contact administrator."
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
        """Update user profile in Firestore"""
        try:
            protected_fields = ['is_admin', 'is_locked', 'activation_key', 'subscription_end']
            for field in protected_fields:
                if field in data:
                    del data[field]
            self.users_collection.document(uid).update(data)
            return True, "Profile updated successfully"
        except Exception as e:
            return False, str(e)

    def lock_user(self, uid, reason=""):
        """Lock a user account"""
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
        """Unlock a user account"""
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
        """Disable a device"""
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
                'expires_at': datetime.datetime.now() + datetime.timedelta(hours=1),
                'upi_id': 'officialnetrasarma@paytm',
                'merchant_name': 'PDF Cropper Pro',
                'transaction_note': f'Credit Purchase - {credits} Credits'
            }
            payment_ref = self.db.collection('payment_requests').document(payment_id)
            payment_ref.set(payment_data)
            self._log_security_event('payment_request_created', user_id=uid, details={
                'payment_id': payment_id,
                'credits': credits,
                'amount': amount
            })
            return True, payment_data
        except Exception as e:
            return False, str(e)

    def _log_security_event(self, event_type, user_id=None, details=None):
        """Log security events"""
        try:
            log_entry = {
                'event_type': event_type,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'user_id': user_id,
                'details': details or {},
                'device_fingerprint': self._get_device_fingerprint()
            }
            self.security_logs_collection.add(log_entry)
        except Exception as e:
            print(f"Error logging security event: {e}")

# Initialize Firebase manager
firebase = FirebaseManager()
