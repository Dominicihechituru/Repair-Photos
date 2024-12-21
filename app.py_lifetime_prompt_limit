from flask import Flask, flash, request, redirect, url_for, render_template, jsonify, make_response, session, abort
from werkzeug.utils import secure_filename
from photo_restorer import predict_image
import os
# below imports are new adds
import pyrebase
from datetime import datetime
import re
import requests
import schedule
import time
import threading


UPLOAD_FOLDER = '/static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000







#************,*****************************
#Start of Added from My Chatbot Githup code



app.secret_key = "your_secret_key"

# Firebase configuration
config = {
    'apiKey': os.environ['firebase_api_key'],
    'authDomain': "cazmir-tech.firebaseapp.com",
    #'authDomain': "refine-photos.onrender.com",
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





@app.route("/")
def login():
    return render_template("login.html")

@app.route("/signup")
def signup():
    return render_template("signup.html")

@app.route("/welcome")
def welcome():
    if session.get("is_logged_in", False):
        return render_template("index.html", email=session["email"], name=session["name"])
    else:
        return redirect(url_for('login'))

def check_password_strength(password):
    return re.match(r'^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$', password) is not None

@app.route("/first-login", methods=["POST", "GET"])
def first_login():
    return render_template("first_login.html")

@app.route("/result", methods=["POST", "GET"])
def result():
    if request.method == "POST":
        result = request.form
        email = result["email"]
        password = result["pass"]
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
            print("Password does not meet strength requirements")
            return redirect(url_for('signup'))
        try:
            auth.create_user_with_email_and_password(email, password)
            user = auth.sign_in_with_email_and_password(email, password)
            auth.send_email_verification(user['idToken'])
            session["is_logged_in"] = True
            session["email"] = user["email"]
            session["uid"] = user["localId"]
            session["name"] = name
            session["prompt_count_db"] = 0
            data = {"name": name, "email": email, "prompt_count_db": 0, "last_logged_in": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")}
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
def logout():
    db.child("users").child(session["uid"]).update({"last_logged_out": datetime.now().strftime("%m/%d/%Y, %H:%M:%S")})
    session["is_logged_in"] = False
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

email_for_paystack=""

@app.route('/subscription', methods=['POST', 'GET'])
def payment():
    global email_for_paystack
    usr_uid = session['uid']
    email_for_paystack= db.child("users").child(usr_uid).child("email").get().val()
    return render_template('payment.html', email=email_for_paystack)
    
'''
email_for_paystack=""

@app.route('/payment', methods=['POST', 'GET'])
def payment():
    global email_for_paystack
    usr_uid = session['uid']
    email_for_paystack= db.child("users").child(usr_uid).child("email").get().val()
    return render_template('payment.html', email=email_for_paystack)
'''
def get_subscription_by_email(email):
    url = "https://api.paystack.co/subscription"
    headers = {
        "Authorization": "Bearer sk_test_9db0fe12af0a5cd5d29b29471888d5057b813522",
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
    url = f"https://check-paystack-api.onrender.com/check_subscription/{subscription_code}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if data.get('message') == "Subscription is active":
            return True
        else:
            return False
    return False

#End of Added from My Chatbot GitHub code
#*********************************************



# Starting of Delete images in folder after some time *********

def delete_files_in_folder():
    folder = "." + UPLOAD_FOLDER  # ensure the correct path is used
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
                print(f"Deleted {file_path}")
        except Exception as e:
            print(f"Error deleting {file_path}: {e}")

# Schedule the deletion jo every 5 minutes
schedule.every(2).hours.do(delete_files_in_folder)

# Function to run the scheduler in a separate thread
def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)

# Start the scheduler thread
scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
scheduler_thread.start()



# Ending of Delete images in folder after some time




# Function to check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
'''
@app.route('/')
def home():
    return render_template('index.html')
'''


@app.route('/upload-page')
def upload_page():

    if not session.get("is_logged_in", False):
        return redirect(url_for('login'))
    return render_template('upload-page.html')


@app.route('/display-page', methods=['POST'])
def upload_file():
    
    email = session.get("email")
    subscription_code_from_email = get_subscription_by_email(email)

    subscription_code = subscription_code_from_email
    print(check_subscription_status(subscription_code))

    
    if not session.get("is_logged_in", False):
        return redirect(url_for('login'))

    # Fetch the current prompt count from the database
    user_data = db.child("users").child(session["uid"]).get().val()
    if not user_data:
        return redirect(url_for('login'))

    # Initialize the session prompt count with the value from the database
    if "prompt_count_db" not in session:
        session["prompt_count_db"] = user_data.get("prompt_count_db", 0)

    # Check if the user has accessed this route more than 2 times
    #if session["prompt_count_db"] >= 2 and not check_subscription_status(subscription_code):
    if session["prompt_count_db"] >= 8 and (not check_subscription_status(subscription_code)):
        return render_template("limit.html")
        #return "limit exeeded"

    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            full_filename = "." + url_for("static", filename="images/" + filename)
            file.save(full_filename)

            predicted_img_url = predict_image(full_filename)

            # Increment the count in both session and database
            session["prompt_count_db"] += 1
            db.child("users").child(session["uid"]).update({"prompt_count_db": session["prompt_count_db"]})

            return render_template("display-page.html", filename=filename, restored_img_url=predicted_img_url)
            
if __name__ == "__main__":
    
    app.run(debug=True, host='0.0.0.0')
