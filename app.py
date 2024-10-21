from flask import Flask, flash, request, redirect, url_for, render_template, jsonify, make_response, session, abort
from werkzeug.utils import secure_filename
from photo_restorer import predict_image
import os
import pyrebase
from datetime import datetime
import re
import requests
import schedule
import time
import threading
from functools import wraps

# Configuration for the Flask application
UPLOAD_FOLDER = '/static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000
app.secret_key = "your_secret_key"  # Change this to a strong secret key

# Firebase configuration
config = {
    'apiKey': os.environ['firebase_api_key'],
    'authDomain': "cazmir-tech.firebaseapp.com",
    'databaseURL': "https://cazmir-tech-default-rtdb.firebaseio.com",
    'projectId': "cazmir-tech",
    'storageBucket': "cazmir-tech.appspot.com",
    'messagingSenderId': "404882482231",
    'appId': "1:404882482231:web:d614535e20f7f55ef1cbb2",
    'measurementId': "G-3F5T0SPESV"
}

# Initialize Firebase
firebase = pyrebase.initialize_app(config)
auth = firebase.auth()
db = firebase.database()

# Decorator to check if a user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_logged_in"):
            return redirect(url_for('login'))  # Redirect to login if not authenticated
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def front_welcome():
    return render_template("front_welcome.html")

@app.route("/firebase-config")
def get_firebase_config():
    # Only send necessary configuration data
    firebase_config = {
        "apiKey": config["apiKey"],
        "authDomain": config["authDomain"],
        "databaseURL": config["databaseURL"],
        "projectId": config["projectId"],
        "storageBucket": config["storageBucket"],
        "messagingSenderId": config["messagingSenderId"],
        "appId": config["appId"],
        "measurementId": config["measurementId"],
    }
    
    response = jsonify(firebase_config)
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

@app.route("/googlesignin", methods=['POST', 'GET'])
def googlesignin():
    if request.method == "POST":
        try:
            # Parse the incoming JSON data
            user_data = request.json
            if not user_data:
                print("No user data provided")
                return jsonify({"message": "No user data provided"}), 400

            # Extract user details from the JSON data
            email = user_data.get("email")
            name = user_data.get("displayName")
            uid = user_data.get("uid")
            
            if not email or not name or not uid:
                print("Incomplete user data:", user_data)
                return jsonify({"message": "Incomplete user data"}), 400

            # Set session variables
            session["is_logged_in"] = True
            session["email"] = email
            session["name"] = name
            session["uid"] = uid

            # Check if the user already exists in the database
            user_exists = db.child("users").child(session["uid"]).get().val()
            if not user_exists:
                # If the user doesn't exist, create a new entry
                data = {
                    "name": name,
                    "email": email,
                    "prompt_count_db": 0,
                    "last_logged_in": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
                }
                db.child("users").child(session["uid"]).set(data)
                print(f"New user {email} added to the database")

            # For existing users, update the last_logged_in time
            else:
                db.child("users").child(session["uid"]).update({"last_logged_in": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")})
                print(f"User {email} login time updated")

            # Redirect to the welcome page or send a success message
            return jsonify({"message": "Sign-in successful"}), 200

        except Exception as e:
            print(f"Error during Google sign-in: {e}")
            return jsonify({"message": "An error occurred during sign-in", "error": str(e)}), 500

    # Handle GET requests by returning a generic response
    return redirect(url_for("welcome"))


@app.route("/signin")
def login():
    return render_template("login.html")

@app.route("/signup")
def signup():
    return render_template("signup.html")

@app.route("/welcome")
@login_required
def welcome():
    return render_template("index.html", email=session["email"], name=session["name"])

def check_password_strength(password):
    return re.match(r'^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$', password) is not None

@app.route("/result", methods=["POST", "GET"])
def login_user():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["pass"]
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            session["is_logged_in"] = True
            session["email"] = user["email"]
            session["uid"] = user["localId"]

            data = db.child("users").get().val()
            if data and session["uid"] in data:
                session["name"] = data[session["uid"]]["name"]
                db.child("users").child(session["uid"]).update({"last_logged_in": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")})
            else:
                session["name"] = "User"
            return redirect(url_for('welcome'))
        except Exception as e:
            print("Error occurred: ", e)
            return redirect(url_for('login'))
    else:
        if session.get("is_logged_in", False):
            return redirect(url_for('welcome'))
        else:
            return redirect(url_for('login'))

@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        result = request.form
        email = result["email"]
        password = result["pass"]
        name = result["name"]
        if not check_password_strength(password):
            return redirect(url_for('signup'))
        try:
            auth.create_user_with_email_and_password(email, password)
            user = auth.sign_in_with_email_and_password(email, password)
            auth.send_email_verification(user['idToken'])
            session["is_logged_in"] = True
            session["email"] = user["email"]
            session["uid"] = user["localId"]
            session["name"] = name
            data = {
                "name": name,
                "email": email,
                "prompt_count_db": 0,
                "last_logged_in": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
            }
            db.child("users").child(session["uid"]).set(data)
            return render_template("verify_email.html")
        except Exception as e:
            print("Error occurred during registration: ", e)
            return redirect(url_for('signup'))
    else:
        if session.get("is_logged_in", False):
            return redirect(url_for('welcome'))
        else:
            return redirect(url_for('signup'))

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        email = request.form["email"]
        try:
            auth.send_password_reset_email(email)
            return render_template("reset_password_done.html")
        except Exception as e:
            print("Error occurred: ", e)
            return render_template("reset_password.html", error="An error occurred. Please try again.")
    else:
        return render_template("reset_password.html")

@app.route("/logout")
@login_required
def logout():
    try:
        db.child("users").child(session["uid"]).update({
            "last_logged_out": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        })
    except Exception as e:
        print(f"Error updating last logged out: {e}")
    session.clear()  # Clear the session
    return redirect(url_for('login'))

@app.route('/landing')
def hello_world():
    return render_template('index.html')

@app.route('/privacypolicy')
def privacypolicy():
    return render_template('privacypolicy.html')

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/contactus')
def contactus():
    return render_template('contactus.html')

email_for_paystack = ""

@app.route('/subscription', methods=['POST', 'GET'])
@login_required
def payment():
    global email_for_paystack
    usr_uid = session['uid']
    email_for_paystack = db.child("users").child(usr_uid).child("email").get().val()
    return render_template('payment.html', email=email_for_paystack)

def get_subscription_by_email(email):
    url = "https://api.paystack.co/subscription"
    headers = {
        "Authorization": "Bearer sk_live_ca56f5de9a6ec2553c20792cfa92d61f8a2a815c",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        subscriptions = response.json().get("data", [])
        for subscription in subscriptions:
            if subscription["customer"]["email"] == email:
                return subscription.get("subscription_code")
    return None

def check_subscription_status(subscription_code):
    url = f"https://check-paystack-status-api.onrender.com/check_subscription/{subscription_code}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if data.get('message') == "Subscription is active":
            return True
        else:
            return False
    return False

# Schedule deletion of images every 2 hours
def delete_files_in_folder():
    folder = "." + UPLOAD_FOLDER  # Ensure the correct path is used
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        if os.path.isfile(file_path):
            os.remove(file_path)  # Delete the file
            print(f"Deleted: {file_path}")

def run_scheduler():
    schedule.every(2).hours.do(delete_files_in_folder)  # Schedule the task to run every 2 hours
    while True:
        schedule.run_pending()
        time.sleep(1)

# Start the scheduler in a separate thread
threading.Thread(target=run_scheduler, daemon=True).start()

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"message": "No file part"}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        # Call the predict_image function to enhance the uploaded image
        restored_image_path = predict_image(file_path)
        return jsonify({"message": "File uploaded successfully", "restored_image": restored_image_path}), 200
    else:
        return jsonify({"message": "File type not allowed"}), 400

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8000)
