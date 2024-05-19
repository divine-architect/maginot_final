# Import necessary modules
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email
from flask_sqlalchemy import SQLAlchemy
import os
import secrets
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import bcrypt
import re
from PIL import Image
import imaplib
import email
from email.header import decode_header
import time
import smtplib
from email.parser import BytesParser
import vt
from flask import Flask, render_template, request
import google.generativeai as genai
from dotenv import load_dotenv
import subprocess
import threading
import os
import subprocess
import threading

# Create the Flask application
app = Flask(__name__)

# Configuration for Flask-WTF and Flask-SQLAlchemy
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'USERDAT'

# Initialize Flask extensions
db = SQLAlchemy(app)
app.config['SESSION_TYPE'] = 'filesystem'

model = genai.GenerativeModel("gemini-pro")
chat = model.start_chat(history=[])


# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# WTForms for Signup
class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Sign Up')

import vt

# Load environment variables for Google Cloud API key
load_dotenv()
genai.configure(api_key=os.getenv('google_key'))

# VirusTotal API Client
client = vt.Client("virus_total_api")

# Gmail credentials (replace with your own)
gmail_user = 'your_email'
gmail_password = 'email_password'

# Download folder for email attachments
download_folder = 'downloads'

def get_latest_email_id(mail):
    """ Retrieves the ID of the latest email in the inbox. """
    mail.select('INBOX')
    status, messages = mail.search(None, 'ALL')
    messages = messages[0].split()
    if messages:
        latest_email_id = messages[-1]
        return latest_email_id
    else:
        return None
def process_attached_image(part):
    """ Processes attached images, including potential virus scanning and company name extraction. """
    filename = part.get_filename()
    if filename:
        download_path = os.path.join(download_folder, filename)
        with open(download_path, "rb") as f:
            analysis = client.scan_file(f)
        print(f"Downloading attachment: {download_path}")
        print(f"Attachment analysis: {analysis}")
        with open(download_path, 'wb') as fp:
            fp.write(part.get_payload(decode=True))

def process_new_email(mail, latest_email_id):
    """ Fetches and processes the email with the given ID. """
    res, msg = mail.fetch(latest_email_id, '(RFC822)')
    raw_email = msg[0][1]
    email_message = email.message_from_bytes(raw_email)
    subject, encoding = decode_header(email_message['Subject'])[0]
    if isinstance(subject, bytes):
        subject = subject.decode(encoding or 'utf-8')
    from_email, encoding = decode_header(email_message['From'])[0]
    if isinstance(from_email, bytes):
        from_email = from_email.decode(encoding or 'utf-8')
    print(f'From: {from_email}')
    print(f'Subject: {subject}')
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                body = part.get_payload(decode=True)
                # Improved prompt for text extraction (consider company names only)
                prompt = f"""Hello Gemini, you are being used to see if an email body contains non-ascii characters and is malicious or not Here is the email details From: {from_email} Subject: {subject} Email content: {body}"""
                response = model.generate_content(prompt, stream=False)
                return response.text
            elif content_type == 'image/jpeg' or content_type == 'image/png':
                
                process_attached_image(part)
            else:
                body = email_message.get_payload(decode=True)
                # Improved prompt for text extraction (consider company names only)
                prompt = f"""Hello Gemini, you are being used to see if an email body contains non-ascii characters and is malicious or not Here is the email details From: {from_email} Subject: {subject} Email content: {body}"""
                response = model.generate_content(prompt, stream=False)
                return response.text


# Generate a random 6-digit OTP
def generate_otp():
    return secrets.token_hex(3)

def hash_password(password):
    # Generate a random salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def message(text, subject="OTP for identity verification"):
    # build message contents
    msg = MIMEMultipart()
    
    # Add Subject
    msg['Subject'] = subject

    # Add text contents
    msg.attach(MIMEText(text))
    return msg

# Send email with OTP
def send_otp_email(email, otp):
    smtp = smtplib.SMTP('smtp.gmail.com', 587)
    smtp.ehlo()
    smtp.starttls()

    # Login with your email and password
    smtp.login('your_email', 'app_passowrd')
    
    to = email
    msg = message(f"Your OTP is: {otp}")
    smtp.sendmail(from_addr="your_email", to_addrs=to, msg=str(msg))
    smtp.quit()

# Routes
@app.route('/')
def home():
    return render_template('index.html')

def run_tier3():
    script_path = os.path.join(os.getcwd(), 'trier.py')
    output_file = os.path.join(os.getcwd(), 'tier3_output.txt')

    with open(output_file, 'w') as f:
        process = subprocess.Popen(['python', script_path], stdout=f, stderr=subprocess.PIPE, universal_newlines=True)
        while True:
            output = process.stderr.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())

    rc = process.poll()
    return rc

@app.route('/social', methods=['GET', 'POST'])
def social_media():
    if request.method == 'POST':
        # Start a new thread to run the tier3.py script
        thread = threading.Thread(target=run_tier3)
        thread.start()
        thread.join()  # Wait for the thread to finish

        # Capture the output lines from the script
        output_lines, rc = thread.get_result()

        # Return the response with the output lines
        return render_template('social.html', output_lines=output_lines)

    return render_template('social.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if request.method == 'POST':
        email = request.form.get('email')
        session['user_email'] = email
        otp = generate_otp()
        session["otp_u"] = otp
        
        send_otp_email(email, otp)

        flash('An email with OTP has been sent. Please check your email and enter the OTP.')
        return redirect(url_for('verify_otp'))

    return render_template('signup.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        user_email = session.get('user_email')
        user_name = request.form.get('username')
        password = request.form.get('password')
        hashed_salted = hash_password(password)

        session['username'] = user_name

        # Query the database for the user with the entered email
        with app.app_context():
            if entered_otp == session.get('otp_u'):
                print("Success")
                with app.app_context():
                    new_user = User(username=user_name, email=user_email, password=hashed_salted)
                    db.session.add(new_user)
                    db.session.commit()
                    
                flash('OTP Verified! You are now signed up.')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid OTP. Please try again.')

    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')  # Encode the entered password to bytes

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password, user.password):
            session['login_username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            # Invalid login credentials
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'login_username' in session:
        return render_template('dashboard.html', username=session['login_username'])
    else:
        return redirect(url_for('login'))



@app.route('/infra')
def infrastructure():
    return "hello word"


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
