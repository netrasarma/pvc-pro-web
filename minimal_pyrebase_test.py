import os
import json
import firebase_admin
from firebase_admin import credentials

def main():
    try:
        mounted_path = os.getenv("FIREBASE_ADMINSDK_MOUNT_PATH")
        if mounted_path and os.path.exists(mounted_path):
            print(f"Found mounted Firebase Admin SDK JSON file at: {mounted_path}")
            cred = credentials.Certificate(mounted_path)
            firebase_admin.initialize_app(cred)
            print("Firebase Admin SDK initialized successfully from mounted file.")
        else:
            firebase_adminsdk_json = os.getenv("FIREBASE_ADMINSDK_JSON")
            if firebase_adminsdk_json:
                print(f"FIREBASE_ADMINSDK_JSON environment variable found with length: {len(firebase_adminsdk_json)}")
                cred_dict = json.loads(firebase_adminsdk_json)
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred)
                print("Firebase Admin SDK initialized successfully from environment variable.")
            else:
                print("FIREBASE_ADMINSDK_JSON environment variable not found, trying local file.")
                cred = credentials.Certificate("firebase-adminsdk.json")
                firebase_admin.initialize_app(cred)
                print("Firebase Admin SDK initialized successfully from local file.")
    except Exception as e:
        print(f"Error initializing Firebase Admin SDK: {e}")

if __name__ == "__main__":
    main()
