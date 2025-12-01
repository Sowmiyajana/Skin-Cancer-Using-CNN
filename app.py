from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_mail import Mail, Message
from PIL import Image
import numpy as np
import skin_cancer_detection as SCD  # Ensure this module is correctly set up
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer  # For secure token generation

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for session management

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your email provider's SMTP server
app.config['MAIL_PORT'] = 587  # For TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Your email address
app.config['MAIL_PASSWORD'] = 'your_app_password'  # Your generated App Password
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@gmail.com'  # Default sender email

mail = Mail(app)

# Initialize URLSafeTimedSerializer for generating tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# Temporary storage for users (in production, use a database)
# Using a dictionary to store usernames with hashed passwords and emails
users = {}

# Ensure classes are defined (this should match your model's output)
SCD.classes = [
    "Actinic keratosis",
    "Basal cell carcinoma",
    "Benign lichenoid keratosis",
    "Dermatofibromas",
    "A melanocytic nevus",
    "Pyogenic granulomas",
    "Melanoma"
]

# Route for Home Page (after login)
@app.route("/", methods=["GET"])
def home():
    if 'username' in session:
        return render_template("home.html", username=session['username'])
    else:
        flash("Please log in to access this page", "danger")
        return redirect(url_for('login'))

# Route for Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].lower()  # Case insensitive comparison
        password = request.form["password"]

        # Debugging: Print all users in the system
        print("Current users in the system:", users)

        # Attempting login
        if username in users:
            if check_password_hash(users[username]['password'], password):
                session['username'] = username
                flash("Login successful!", "success")
                return redirect(url_for("home"))
            else:
                flash("Incorrect password", "danger")
        else:
            flash("Username not found", "danger")
    return render_template("login.html")

# Route for Registration Page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].lower()  # Case insensitive username
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        email = request.form["email"]

        # Check if username already exists
        if username in users:
            flash("Username already exists", "warning")
        elif password != confirm_password:
            flash("Passwords do not match!", "danger")
        elif not email:
            flash("Email is required!", "danger")  # Ensure email is provided
        else:
            # Store the hashed password and email
            users[username] = {
                'password': generate_password_hash(password),
                'email': email  # Store email for password reset
            }
            print(f"User registered successfully: {username}")  # Debugging: User registration success
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("page1.html")

# Route for Forgot Password
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        # Find the user by email
        user_found = False
        for user, details in users.items():
            print(f"Checking: {details['email']} against {email}")  # Debugging statement
            if details['email'] == email:
                user_found = True
                # Generate a password reset token
                reset_token = serializer.dumps(email, salt='password-reset-salt')  # Generate a secure token
                reset_link = url_for('reset_password', token=reset_token, _external=True)  # Create a full URL
                
                # Send the email
                msg = Message("Password Reset Request", recipients=[email])
                msg.body = f"To reset your password, click the following link: {reset_link}"
                try:
                    mail.send(msg)
                    flash("A password reset link has been sent to your email.", "success")
                except Exception as e:
                    flash(f"Error sending email: {str(e)}", "danger")
                break

        if not user_found:
            flash("Email not found!", "danger")

        return redirect(url_for("login"))

    return render_template("forgot_password.html")

# Route for Reset Password
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # Token valid for 1 hour
    except Exception:
        flash("The password reset link is invalid or has expired.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form["new_password"]
        # Update the user's password
        for user, details in users.items():
            if details['email'] == email:
                users[user]['password'] = generate_password_hash(new_password)  # Update the password
                flash("Your password has been reset successfully.", "success")
                return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

# Logout Route
@app.route("/logout")
def logout():
    session.pop('username', None)
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

# Route for Skin Cancer Detection Result Page
@app.route("/showresult", methods=["POST"])
def show():
    if 'username' not in session:
        flash("Please log in to access this page", "danger")
        return redirect(url_for('login'))

    if 'pic' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('home'))
    
    pic = request.files["pic"]

    # Ensure a file is selected
    if pic.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('home'))

    try:
        # Process the uploaded image
        input_img = Image.open(pic)

        # Check image mode and convert to RGB if needed
        if input_img.mode != 'RGB':
            input_img = input_img.convert('RGB')

        input_img = input_img.resize((28, 28))  # Resize to match model input size
        img = np.array(input_img).reshape(-1, 28, 28, 3)  # Reshape for model input

        # Predict using the trained model
        result = SCD.model.predict(img)

        # Check if the model's output is valid
        if not isinstance(result, np.ndarray) or result.size == 0:
            raise ValueError("Model output is not a valid array")

        # Extract the most probable result
        max_prob = max(result[0])
        class_ind = result[0].tolist().index(max_prob)

        # Get detected skin condition
        detected_condition = SCD.classes[class_ind]

        # Retrieve additional information about the condition
        info = get_condition_info(class_ind)

        return render_template("reults.html", result=detected_condition, info=info)

    except Exception as e:
        print(f"Error processing image: {e}")  # Log the error for debugging
        flash(f"Error processing the image: {e}. Please ensure it is a valid image.", "danger")
        return redirect(url_for('home'))

# Helper function to map class index to condition information
def get_condition_info(class_ind):
    conditions = {
        0: "Actinic keratosis: A pre-cancerous skin condition.",
        1: "Basal cell carcinoma: A common form of skin cancer.",
        2: "Benign lichenoid keratosis (BLK): A non-cancerous skin growth.",
        3: "Dermatofibromas: Non-cancerous skin growths.",
        4: "A melanocytic nevus: Commonly known as a mole.",
        5: "Pyogenic granulomas: Benign skin growths.",
        6: "Melanoma: The most serious type of skin cancer."
    }
    return conditions.get(class_ind, "Unknown condition.")

if __name__ == "__main__":
    app.run(debug=True)
