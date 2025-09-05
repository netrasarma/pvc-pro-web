import datetime
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from firebase_config import firebase, FIREBASE_CONFIG  # Import your firebase manager and config
import firebase_admin
from firebase_admin import firestore
import hmac
import hashlib
import os
import uuid
import traceback
import logging
import requests
import io
import base64
from document_processor import AadharProcessor, PanProcessor, VoterProcessor, DLProcessor, RCProcessor, ABHAProcessor, AyushmanProcessor, EshramProcessor
import razorpay

# Setup basic logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
CORS(app)
# IMPORTANT: Set a secret key for session management.
app.secret_key = 'pvc-pro-a-very-secret-and-random-key-12345'

# --- Environment Variables ---
# These are loaded from your Cloud Run service settings
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET")

# Initialize Razorpay client
if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
    razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    app.logger.info("Razorpay client initialized successfully")
else:
    app.logger.error("Razorpay credentials not configured")
    razorpay_client = None

# --- Main Routes (Pages) ---

@app.route("/")
def render_homepage():
    """Renders the main homepage."""
    return render_template('index.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            # Use unified sign_in method
            success, user = firebase.sign_in(email, password)
            print(f"Login attempt for {email}, success: {success}, user: {user}")
            if not success:
                return render_template('login.html', error=user, firebase_config=FIREBASE_CONFIG)

            # Store user token dict in session as 'user_token'
            session['user_token'] = user

            # Fetch user profile and store in session
            uid = user.get('localId') or user.get('local_id') or user.get('userId')
            if not uid:
                print(f"UID not found in user token for {email}: {user}")
                return render_template('login.html', error="Login failed: User ID not found.", firebase_config=FIREBASE_CONFIG)

            success_profile, user_profile = firebase.get_user_profile(uid)
            if success_profile:
                session['user'] = user_profile
            else:
                session['user'] = {}

            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Exception during login for {email}: {e}")
            return render_template('login.html', error="Invalid email or password.", firebase_config=FIREBASE_CONFIG)
    else:
        # GET request
        return render_template('login.html', firebase_config=FIREBASE_CONFIG)

from flask import request, jsonify

@app.route("/forgot_password", methods=['POST'])
def forgot_password():
    import traceback
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({"error": "Please enter your email address."}), 400
    # Implement validate_email here since FirebaseManager lacks it
    import re
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    if not validate_email(email):
        return jsonify({"error": "Please enter a valid email address."}), 400
    try:
        # Check if user exists before sending reset link
        user_query = firebase.db.collection('users').where('email', '==', email).limit(1).get()
        if not user_query:
            return jsonify({"error": "User not registered with this email address."}), 400

        firebase.auth.send_password_reset_email(email)
        # On success, redirect to login page
        return jsonify({"message": "Password reset link sent to your email!", "redirect": "/login"}), 200
    except Exception as e:
        error_msg = str(e)
        app.logger.error(f"Password reset error for {email}: {error_msg}")
        app.logger.error(traceback.format_exc())
        if "EMAIL_NOT_FOUND" in error_msg:
            return jsonify({"error": "No account found with this email address."}), 400
        elif "INVALID_EMAIL" in error_msg:
            return jsonify({"error": "Invalid email address."}), 400
        else:
            return jsonify({"error": "Failed to send reset link. Please try again."}), 500

@app.route("/register", methods=['GET', 'POST'])
def register():
    """Handles new user registration."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        mobile = request.form['mobile']
        user_data = {
            "name": name,
            "mobile": mobile,
            "registered_on": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "is_activated": False,
            "is_admin": False,
            "activation_key": "",
            "subscription_start": "",
            "subscription_end": "",
            "status": "Registered"
        }
        success, result = firebase.create_user(email, password, user_data)
        if success:
            # Try to sign in the user immediately after registration to verify credentials
            sign_in_success, sign_in_result = firebase.sign_in(email, password)
            if sign_in_success:
                flash('Congratulations! Registration successful. You are now logged in.', 'success')
                session['user'] = sign_in_result
                return redirect(url_for('dashboard'))
            else:
                flash('Registration successful but automatic login failed. Please login manually.', 'warning')
                return redirect(url_for('login'))
        else:
            error = result
            if 'EMAIL_EXISTS' in error:
                error = "This email address is already in use."
            return render_template('register.html', error=error, firebase_config=FIREBASE_CONFIG)
    return render_template('register.html', firebase_config=FIREBASE_CONFIG)

@app.route("/dashboard")
def dashboard():
    """Displays the user's dashboard."""
    if 'user' in session:
        user_id = session['user'].get('uid') or session['user'].get('localId') or session['user'].get('id')
        if not user_id:
            # Clear session and redirect to login if user ID is missing
            session.pop('user', None)
            session.pop('user_token', None)
            return redirect(url_for('login'))
        
        user_profile_doc = firebase.db.collection('users').document(user_id).get()
        if user_profile_doc.exists:
            user_data = user_profile_doc.to_dict()
            session['user'] = user_data
            
            # Fetch user's credit transaction history
            try:
                # First get all transactions for the user, then sort them locally
                transactions_query = firebase.db.collection('credit_transactions')\
                    .where('user_id', '==', user_id)\
                    .get()
                transactions = [tx.to_dict() for tx in transactions_query]
                
                # Sort transactions by timestamp descending locally
                transactions.sort(key=lambda x: x.get('timestamp', datetime.datetime.min), reverse=True)
                
                # Limit to 20 most recent
                transactions = transactions[:20]
            except Exception as e:
                transactions = []
            
            # Check if user is locked and show message on dashboard
            if user_data.get('is_locked', False):
                admin_contact = "officialnetrasarma@gmail.com"
                lock_message = f"Your account is locked. Please contact admin at {admin_contact} to unlock."
                return render_template('dashboard.html', user=user_data, lock_message=lock_message, transactions=transactions)
            
            return render_template('dashboard.html', user=user_data, transactions=transactions)
    return redirect(url_for('login'))

@app.route("/change_password", methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        user_token = session.get('user_token')
        email = user_token.get('email') if user_token else None
        
        if not email:
            return redirect(url_for('login'))
        
        # Verify old password by attempting sign in
        success, result = firebase.sign_in(email, old_password)
        if not success:
            error = "Old password is incorrect."
            return render_template('change_password.html', error=error)
        
        # Update password using Firebase Admin SDK
        try:
            user_id = user_token.get('localId')
            firebase_admin.auth.update_user(user_id, password=new_password)
            message = "Password changed successfully."
            return render_template('change_password.html', message=message)
        except Exception as e:
            error = f"Failed to change password: {str(e)}"
            return render_template('change_password.html', error=error)
    
    return render_template('change_password.html')

@app.route("/logout")
def logout():
    """Logs the user out."""
    session.pop('user', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('render_homepage'))

# --- API and Webhook Routes ---

@app.route("/create_razorpay_order", methods=["POST"])
def create_razorpay_order():
    """API endpoint to create a Razorpay payment order."""
    if 'user' not in session:
        return jsonify({"error": "User not logged in"}), 401

    data = request.json
    user_id = session['user']['uid']

    amount = data.get("amount")
    currency = data.get("currency", "INR")
    receipt = data.get("receipt", f"receipt_{uuid.uuid4().hex}")

    try:
        if not razorpay_client:
            return jsonify({"error": "Payment service not configured"}), 500

        razorpay_order = razorpay_client.order.create({
            "amount": amount,
            "currency": currency,
            "receipt": receipt,
            "notes": {"user_id": user_id},
            "payment_capture": 1
        })

        app.logger.info(f"Created Razorpay order: {razorpay_order}")

        return jsonify({
            "order_id": razorpay_order.get("id"),
            "amount": razorpay_order.get("amount"),
            "currency": razorpay_order.get("currency"),
            "key_id": RAZORPAY_KEY_ID
        })
    except Exception as e:
        app.logger.error(f"Error creating Razorpay order: {e}")
        return jsonify({"error": "Could not create payment order."}), 500

@app.route("/razorpay-webhook", methods=['POST'])
def razorpay_webhook():
    """Webhook endpoint to handle Razorpay payment confirmations."""
    try:
        # Get the raw request data
        raw_data = request.get_data()
        signature = request.headers.get('X-Razorpay-Signature')

        if not signature:
            app.logger.error("No signature provided in webhook")
            return jsonify({"error": "No signature"}), 400

        # Verify the webhook signature
        expected_signature = hmac.new(
            RAZORPAY_WEBHOOK_SECRET.encode(),
            raw_data,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            app.logger.error("Invalid webhook signature")
            return jsonify({"error": "Invalid signature"}), 400

        # Parse the webhook data
        webhook_data = request.get_json()
        app.logger.info(f"Received Razorpay webhook: {webhook_data}")

        # Process the payment based on the event type
        event = webhook_data.get('event')

        if event == 'payment.captured':
            payment_entity = webhook_data.get('payload', {}).get('payment', {}).get('entity', {})
            order_id = payment_entity.get('order_id')
            payment_id = payment_entity.get('id')
            amount = payment_entity.get('amount')  # Amount in paise

            # Get order details to find user ID
            try:
                if not razorpay_client:
                    app.logger.error("Razorpay client not initialized")
                    return jsonify({"error": "Payment service not configured"}), 500

                order_details = razorpay_client.order.fetch(order_id)
                notes = order_details.get('notes', {})
                user_id = notes.get('user_id')

                if not user_id:
                    app.logger.error("No user ID found in order notes")
                    return jsonify({"error": "No user ID"}), 400

                # Convert amount from paise to rupees and calculate credits
                amount_rupees = int(amount) / 100
                credits = int(amount_rupees)  # ₹1 per credit

                # Add credits to user account
                success, result = firebase.add_user_credits(user_id, credits)

                if success:
                    app.logger.info(f"Successfully added {credits} credits to user {user_id}")
                    return jsonify({"status": "success"}), 200
                else:
                    app.logger.error(f"Failed to add credits: {result}")
                    return jsonify({"error": "Failed to add credits"}), 500

            except Exception as order_error:
                app.logger.error(f"Error fetching order details: {order_error}")
                return jsonify({"error": "Order fetch failed"}), 500

        return jsonify({"status": "ignored"}), 200

    except Exception as e:
        app.logger.error(f"Webhook error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/process", methods=["POST"])
def process_document():
    if 'user' not in session:
        return jsonify({"error": "User not logged in"}), 401

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    app.logger.info(f"Uploaded file: filename={file.filename}, content_type={file.content_type}")
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    doc_type = request.form.get('doc_type')
    if not doc_type:
        return jsonify({"error": "Document type not specified"}), 400

    # Get password from request if provided
    password = request.form.get('password', None)

    try:
        # First check if user has enough credits
        user_id = session['user']['uid']
        user_credits = session['user'].get('credits', 0)
        
        if user_credits < 1:
            return jsonify({"error": "Insufficient credits. Please recharge your account."}), 402

        file_stream = io.BytesIO(file.read())
        processor = None

        if doc_type == "aadhar":
            processor = AadharProcessor(file_stream, password)
        elif doc_type == "pan":
            processor = PanProcessor(file_stream, password)
        elif doc_type == "voter":
            processor = VoterProcessor(file_stream, password)
        elif doc_type == "dl":
            processor = DLProcessor(file_stream, password)
        elif doc_type == "rc":
            processor = RCProcessor(file_stream, password)
        elif doc_type == "abha":
            processor = ABHAProcessor(file_stream, password)
        elif doc_type == "ayushman":
            processor = AyushmanProcessor(file_stream, password)
        elif doc_type == "eshram":
            processor = EshramProcessor(file_stream, password)
        else:
            return jsonify({"error": "Invalid document type"}), 400

        if processor:
            processed_images = processor.process()
            app.logger.info(f"Processing completed for user {user_id}. Images produced: {list(processed_images.keys()) if processed_images else 'None'}")

            # Validate that we have valid processed images
            if not processed_images or len(processed_images) == 0:
                app.logger.error(f"No images produced from processing for user {user_id}")
                return jsonify({"error": "Document processing failed: No valid images could be extracted. Please check your document format and try again."}), 422

            # Validate image quality and content
            valid_images = {}
            for side, img in processed_images.items():
                app.logger.info(f"Validating image {side}: {img.width}x{img.height}")

                # Check if image has reasonable dimensions (not too small)
                if img.width < 100 or img.height < 100:
                    app.logger.warning(f"Image {side} too small: {img.width}x{img.height}")
                    continue

                # Check if image is not completely blank/empty
                # Convert to grayscale and check if it's mostly white/empty
                img_gray = img.convert('L')
                pixels = list(img_gray.getdata())
                avg_brightness = sum(pixels) / len(pixels)
                app.logger.info(f"Image {side} avg brightness: {avg_brightness}")

                # If image is too bright (mostly white), it might be empty
                if avg_brightness > 250:  # Very bright = likely empty
                    app.logger.warning(f"Image {side} appears to be empty/blank (avg brightness: {avg_brightness})")
                    continue

                valid_images[side] = img

            app.logger.info(f"Valid images after quality check: {list(valid_images.keys())}")

            if not valid_images:
                app.logger.error(f"No valid images after quality check for user {user_id}")
                return jsonify({"error": "Document processing failed: Extracted images appear to be blank or corrupted. Please ensure your document is clear and properly scanned."}), 422

            response_images = {}
            for side, img in valid_images.items():
                buffered = io.BytesIO()
                img.save(buffered, format="PNG")
                img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
                response_images[side] = img_str

            # Only deduct credit if we have valid processed images
            doc_type_name = doc_type.upper() if doc_type else "DOCUMENT"

            # Double check user credits before deducting to avoid race conditions
            user_ref = firebase.db.collection('users').document(user_id)
            user_doc = user_ref.get()
            if not user_doc.exists:
                return jsonify({"error": "User not found"}), 404
            user_data = user_doc.to_dict()
            current_credits = user_data.get('credits', 0)
            if current_credits < 1:
                return jsonify({"error": "Insufficient credits. Please recharge your account."}), 402

            success, new_balance = firebase.deduct_user_credit(
                user_id,
                1,
                f"Document processing: {doc_type_name} card"
            )
            if not success:
                app.logger.error(f"Failed to deduct credits for user {user_id}: {new_balance}")
                return jsonify({"error": "Failed to process payment. Please try again."}), 500

            # Update user session with new balance
            session['user']['credits'] = new_balance

            # Update documents processed count
            try:
                user_ref = firebase.db.collection('users').document(user_id)
                user_doc = user_ref.get()
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    documents_processed = user_data.get('documents_processed', 0)
                    total_spent = user_data.get('total_spent', 0)

                    user_ref.update({
                        'documents_processed': documents_processed + 1,
                        'total_spent': total_spent + 1,
                        'last_processed': firestore.SERVER_TIMESTAMP
                    })
            except Exception as e:
                app.logger.error(f"Failed to update user stats: {e}")

            return jsonify(response_images)
        else:
            return jsonify({"error": "Processor not initialized"}), 500

    except Exception as e:
        app.logger.error(f"Error processing document: {e}")
        app.logger.error(traceback.format_exc())
        error_msg = str(e)
        if "password protected" in error_msg.lower() or "password is not correct" in error_msg.lower():
            return jsonify({"error": "PASSWORD_REQUIRED", "message": error_msg}), 403
        return jsonify({"error": f"Document processing failed: {error_msg}"}), 500

@app.route("/api/user_dashboard_data")
def user_dashboard_data():
    """API endpoint to get user dashboard data (credits and recent transactions)"""
    if 'user' not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    try:
        user_id = session['user']['uid']
        
        # Get user credits
        user_ref = firebase.db.collection('users').document(user_id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404
        
        user_data = user_doc.to_dict()
        credits = user_data.get('credits', 0)
        
        # Get recent transactions
        transactions_query = firebase.db.collection('credit_transactions')\
            .where('user_id', '==', user_id)\
            .order_by('timestamp', direction=firestore.Query.DESCENDING)\
            .limit(10)\
            .get()
        
        transactions = []
        for tx in transactions_query:
            tx_data = tx.to_dict()
            # Convert Firestore timestamp to ISO string for JSON serialization
            if 'timestamp' in tx_data and hasattr(tx_data['timestamp'], 'isoformat'):
                tx_data['timestamp'] = tx_data['timestamp'].isoformat()
            transactions.append(tx_data)
        
        return jsonify({
            "credits": credits,
            "recent_transactions": transactions
        })
        
    except Exception as e:
        app.logger.error(f"Error fetching user dashboard data: {e}")
        return jsonify({"error": "Failed to fetch dashboard data"}), 500

@app.route("/api/update_profile", methods=["POST"])
def update_profile():
    """API endpoint to update user profile information"""
    if 'user' not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    try:
        user_id = session['user']['uid']
        data = request.get_json()
        
        # Validate input
        if not data.get('name'):
            return jsonify({"error": "Name is required"}), 400
        
        # Update user profile in Firestore
        user_ref = firebase.db.collection('users').document(user_id)
        update_data = {
            'name': data['name'],
            'mobile': data.get('mobile', '')
        }
        
        user_ref.update(update_data)
        
        # Update session data
        session['user']['name'] = data['name']
        session['user']['mobile'] = data.get('mobile', '')
        
        return jsonify({
            "success": True,
            "message": "Profile updated successfully",
            "user": {
                "name": data['name'],
                "mobile": data.get('mobile', '')
            }
        })
        
    except Exception as e:
        app.logger.error(f"Error updating profile: {e}")
        return jsonify({"error": "Failed to update profile"}), 500

@app.route("/api/contact_support", methods=["POST"])
def contact_support():
    """API endpoint to handle support contact form submissions"""
    if 'user' not in session:
        return jsonify({"error": "User not logged in"}), 401
    
    try:
        user_id = session['user']['uid']
        data = request.get_json()
        
        # Validate input
        if not data.get('subject'):
            return jsonify({"error": "Subject is required"}), 400
        if not data.get('message'):
            return jsonify({"error": "Message is required"}), 400
        if not data.get('email'):
            return jsonify({"error": "Email is required"}), 400
        
        # Store support ticket in Firestore
        support_data = {
            'user_id': user_id,
            'user_name': session['user'].get('name', ''),
            'user_email': data['email'],
            'subject': data['subject'],
            'message': data['message'],
            'status': 'new',
            'created_at': firestore.SERVER_TIMESTAMP,
            'updated_at': firestore.SERVER_TIMESTAMP
        }
        
        firebase.db.collection('support_tickets').add(support_data)
        
        # TODO: Send email notification to support team
        # You can integrate with email service here
        
        return jsonify({
            "success": True,
            "message": "Support message sent successfully. We will get back to you soon."
        })
        
    except Exception as e:
        app.logger.error(f"Error processing support request: {e}")
        return jsonify({"error": "Failed to send support message"}), 500

@app.route("/api/google_auth", methods=["POST"])
def google_auth():
    data = request.get_json()
    id_token = data.get('id_token')

    if not id_token:
        return jsonify({"error": "ID token is missing"}), 400

    try:
        # Verify the ID token
        decoded_token = firebase_admin.auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        email = decoded_token['email']
        name = decoded_token.get('name', email) # Use email as name if not provided by Google

        # Check if user exists in Firebase Auth, if not, create them
        try:
            user_record = firebase_admin.auth.get_user(uid)
        except firebase_admin.auth.UserNotFoundError:
            # User does not exist, create them
            user_record = firebase_admin.auth.create_user(
                uid=uid,
                email=email,
                display_name=name,
                email_verified=True # Google verifies email
            )
            # Also create user profile in Firestore
            user_data = {
                "name": name,
                "email": email,
                "registered_on": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "is_activated": False,
                "is_admin": False,
                "activation_key": "",
                "subscription_start": "",
                "subscription_end": "",
                "status": "Registered",
                "uid": uid,
                "credits": 0 # Initialize credits
            }
            firebase.db.collection('users').document(uid).set(user_data)

        # Sign in the user into Flask session
        # This part needs to mimic the existing sign_in logic to set session['user']
        # For simplicity, we'll just set the session directly based on decoded_token
        user_doc_ref = firebase.db.collection('users').document(uid)
        user_doc = user_doc_ref.get()
        if user_doc.exists:
            credits = user_doc.to_dict().get('credits', 0)
        else:
            # This case should ideally not happen if user is created above,
            # but as a fallback, initialize credits to 0 and create the document
            # if it doesn't exist for some reason.
            user_data = {
                "name": name,
                "email": email,
                "registered_on": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "is_activated": False,
                "is_admin": False,
                "activation_key": "",
                "subscription_start": "",
                "subscription_end": "",
                "status": "Registered",
                "uid": uid,
                "credits": 0
            }
            firebase.db.collection('users').document(uid).set(user_data)
            credits = 0

        session['user'] = {
            'uid': uid,
            'localId': uid, # For compatibility with existing code
            'email': email,
            'name': name,
            'is_activated': user_record.custom_claims.get('is_activated', False) if user_record.custom_claims else False,
            'credits': credits # Fetch current credits
        }
        session['user_token'] = decoded_token # Store the decoded token if needed elsewhere

        flash('Login successful!', 'success')
        return jsonify({"message": "Google login successful", "redirect": url_for('dashboard')}), 200

    except ValueError as e:
        app.logger.error(f"Invalid ID token: {e}")
        return jsonify({"error": "Invalid ID token"}), 401
    except Exception as e:
        app.logger.error(f"Error during Google auth: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({"error": "Google authentication failed"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
