import datetime
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from firebase_config import firebase  # Import your firebase manager
import firebase_admin
from firebase_admin import firestore
import hmac
import hashlib
import os
import uuid
import traceback
import logging
import requests

# Setup basic logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
# IMPORTANT: Set a secret key for session management.
app.secret_key = 'pvc-pro-a-very-secret-and-random-key-12345'

# --- Environment Variables ---
# These are loaded from your Cloud Run service settings
CASHFREE_APP_ID = os.getenv("CASHFREE_APP_ID")
CASHFREE_SECRET_KEY = os.getenv("CASHFREE_SECRET_KEY")
CASHFREE_WEBHOOK_SECRET = os.getenv("CASHFREE_WEBHOOK_SECRET")

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
                return render_template('login.html', error=user)
            
            # Store user token dict in session as 'user_token'
            session['user_token'] = user
            
            # Fetch user profile and store in session
            uid = user['localId']
            success_profile, user_profile = firebase.get_user_profile(uid)
            if success_profile:
                session['user'] = user_profile
            else:
                session['user'] = {}
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            print(f"Exception during login for {email}: {e}")
            return render_template('login.html', error="Invalid email or password.")
    else:
        # GET request
        return render_template('login.html')

from flask import request, jsonify

@app.route("/forgot_password", methods=['POST'])
def forgot_password():
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
            return render_template('register.html', error=error)
    return render_template('register.html')

@app.route("/dashboard")
def dashboard():
    """Displays the user's dashboard."""
    if 'user' in session:
        user_id = session['user']['uid']
        user_profile_doc = firebase.db.collection('users').document(user_id).get()
        if user_profile_doc.exists:
            user_data = user_profile_doc.to_dict()
            session['user'] = user_data
            
            # Check if user is locked and show message on dashboard
            if user_data.get('is_locked', False):
                admin_contact = "officialnetrasarma@gmail.com"
                lock_message = f"Your account is locked. Please contact admin at {admin_contact} to unlock."
                return render_template('dashboard.html', user=user_data, lock_message=lock_message)
            
            return render_template('dashboard.html', user=user_data)
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

@app.route("/create_order", methods=["POST"])
def create_order():
    """API endpoint to create a payment order."""
    if 'user' not in session:
        return jsonify({"error": "User not logged in"}), 401

    data = request.json
    user_id = session['user']['uid']
    
    # <-- 2. DEFINE CASHFREE VARIABLES LOCALLY
    CASHFREE_URL = "https://api.cashfree.com/pg/orders"
    HEADERS = {
        "Content-Type": "application/json",
        "x-api-version": "2022-09-01",
        "x-client-id": CASHFREE_APP_ID,
        "x-client-secret": CASHFREE_SECRET_KEY
    }
    
    order_id = "ORDER_" + str(uuid.uuid4()).replace("-", "")[:12]
    
    order_data = {
        "order_id": order_id,
        "order_amount": data.get("order_amount"),
        "order_currency": "INR",
        "order_note": data.get("order_note"),
        "customer_details": {
            "customer_id": user_id,
            "customer_email": session['user']['email'],
            "customer_phone": session['user'].get('mobile', ''),
            "customer_name": session['user']['name']
        },
        "order_meta": {
             "notify_url": url_for('cashfree_webhook', _external=True)
        },
        "order_tags": {
            "internal_user_id": user_id
        }
    }

    try:
        response = requests.post(CASHFREE_URL, headers=HEADERS, json=order_data)
        response.raise_for_status()
        result = response.json()
        return jsonify({"paymentSessionId": result.get("payment_session_id")})
    except Exception as e:
        app.logger.error(f"Error creating order: {e}")
        return jsonify({"error": "Could not create payment order."}), 500

@app.route("/cashfree-webhook", methods=['POST'])
def cashfree_webhook():
    """Handles incoming webhooks from Cashfree."""
    app.logger.info("--- Webhook Received ---")
    try:
        raw_body = request.get_data()
        received_signature = request.headers.get('x-webhook-signature')
        timestamp = request.headers.get('x-webhook-timestamp')

        if not received_signature or not timestamp or not CASHFREE_WEBHOOK_SECRET:
            app.logger.error("Webhook missing headers or server-side secret key.")
            return jsonify({"error": "Configuration error"}), 400

        payload = f"{timestamp}{raw_body.decode('utf-8')}"
        computed_signature = hmac.new(key=CASHFREE_WEBHOOK_SECRET.encode('utf-8'), msg=payload.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

        if not hmac.compare_digest(computed_signature, received_signature):
            app.logger.error("Webhook signature verification failed.")
            return jsonify({"error": "Signature mismatch"}), 400
        
        app.logger.info("Webhook signature verified successfully!")
        
        webhook_data = request.get_json()
        order_data = webhook_data.get('data', {}).get('order', {})
        payment_status = order_data.get('order_status')
        
        if payment_status == 'PAID':
            user_id = order_data.get('order_tags', {}).get('internal_user_id')
            if user_id:
                order_note = order_data.get('order_note', '')
                if "Annual Subscription" in order_note:
                    keys_query = firebase.db.collection('activation_keys').where('status', '==', 'UNUSED').limit(1).get()
                    if keys_query:
                        key_doc = keys_query[0]
                        firebase.activate_user(user_id, key_doc.id)
                elif "File Credits" in order_note:
                    amount = float(order_data.get('order_amount', 0))
                    credits_to_add = int(amount)
                    firebase.add_user_credits(user_id, credits_to_add)
        
        return jsonify({"status": "ok"}), 200

    except Exception as e:
        app.logger.error("--- An error occurred in the webhook handler ---")
        app.logger.error(traceback.format_exc())
        return jsonify({"error": "Webhook processing error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
