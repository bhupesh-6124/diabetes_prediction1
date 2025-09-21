from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer 
import random
import pickle
import joblib
import os
from mysql import connector
import random
import nltk
from flask import Flask, render_template, request, jsonify
from datetime import datetime
import cryptography
import sqlite3

nltk.download('punkt')
nltk.download('wordnet')
nltk.download('omw-1.4')
nltk.download('stopwords')



app = Flask(__name__)

app.secret_key = 'your_secret_key'

# Database and Mail Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:GHdLuaKdNOgzJePesfJQbQdquHwXiSrF@trolley.proxy.rlwy.net:35481/railway"

# app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:GHdLuaKdNOgzJePesfJQbQdquHwXiSrF@containers-us-west-123.railway.app:3306/railway"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] =  'wankhadebhupesh424@gmail.com'
app.config['MAIL_PASSWORD'] = 'mkvw pozd gdwp axxo'
mail = Mail(app)

bcrypt = Bcrypt(app)
s = URLSafeTimedSerializer(app.secret_key) 

model = joblib.load("diabetes_model.pkl")
scaler = joblib.load("scaler.pkl")

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    otp = db.Column(db.String(6), nullable=True)

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pregnancies = db.Column(db.Float, nullable=False)
    glucose = db.Column(db.Float, nullable=False)
    blood_pressure = db.Column(db.Float, nullable=False)
    skin_thickness = db.Column(db.Float, nullable=False)
    insulin = db.Column(db.Float, nullable=False)
    bmi = db.Column(db.Float, nullable=False)
    dpf = db.Column(db.Float, nullable=False)
    age = db.Column(db.Float, nullable=False)
    result = db.Column(db.String(20), nullable=False)
    diabetic_probability = db.Column(db.Float, nullable=False)
    non_diabetic_probability = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        address = request.form['address']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')  # Hash password
        otp = str(random.randint(100000, 999999))  # Generate OTP

        # Save user with OTP
        user = User(name=name, address=address, email=email, password=password, otp=otp)
        db.session.add(user)
        db.session.commit()

        # Send OTP to email
        msg = Message('Your OTP for Signup', sender='your_email@gmail.com', recipients=[email])
        msg.body = f'Your OTP is: {otp}'
        mail.send(msg)

        flash('An OTP has been sent to your email. Please verify.', 'info')
        session['user_email'] = email  # Store email in session for verification
        return redirect(url_for('verify_otp'))
    return render_template('signup.html')

# OTP Verification Route
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('user_email')
    user = User.query.filter_by(email=email).first()

    if not user:
        flash('User session expired. Please sign up again.', 'danger')
        return redirect(url_for('signup'))

    if request.method == 'POST':
        otp = request.form['otp']

        if user.otp == otp:
            user.otp = None  # Clear OTP after successful verification
            db.session.commit()
            flash('Signup successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_otp.html', user=user)

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):  # Check hashed password
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

# Forgot Password Route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a password reset token
            token = s.dumps(email, salt='password-reset-salt')

            # Create reset link
            reset_link = url_for('reset_password', token=token, _external=True)

            # Send reset password email
            msg = Message('Password Reset Request', sender='your_email@gmail.com', recipients=[email])
            msg.body = f'Click here to reset your password: {reset_link}'
            mail.send(msg)

            flash('Password reset link sent to your email.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found. Please try again.', 'danger')

    return render_template('forgot_password.html')

# Reset Password Route
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Verify token and get the email
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # Token expires in 1 hour
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')  # Hash new password
        user = User.query.filter_by(email=email).first()
        user.password = new_password
        db.session.commit()

        flash('Your password has been reset successfully. You can now log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# Resend OTP Route
@app.route('/resend-otp', methods=['GET'])
def resend_otp():
    email = session.get('user_email')
    user = User.query.filter_by(email=email).first()

    if user:
        otp = str(random.randint(100000, 999999))  # Generate new OTP
        user.otp = otp
        db.session.commit()

        # Send new OTP to email
        msg = Message('Your OTP for Signup', sender='your_email@gmail.com', recipients=[email])
        msg.body = f'Your new OTP is: {otp}'
        mail.send(msg)

        flash('A new OTP has been sent to your email.', 'info')
        return redirect(url_for('verify_otp'))

    flash('Something went wrong. Please try again.', 'danger')
    return redirect(url_for('signup'))

@app.template_filter('format_date')
def format_date(value):
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d')
    return ''




# Prediction Route
@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Extract and store all inputs
        inputs = {
            'Pregnancies': float(request.form['Pregnancies']),
            'Glucose': float(request.form['Glucose']),
            'BloodPressure': float(request.form['BloodPressure']),
            'SkinThickness': float(request.form['SkinThickness']),
            'Insulin': float(request.form['Insulin']),
            'BMI': float(request.form['BMI']),
            'DiabetesPedigreeFunction': float(request.form['DiabetesPedigreeFunction']),
            'Age': float(request.form['Age'])
        }

        input_list = list(inputs.values())
        prediction = model.predict([input_list])[0]
        probabilities = model.predict_proba([input_list])[0]

        # ✅ Ensure native Python float, not NumPy float64
        diabetic_probability = float(round(probabilities[1] * 100, 2))
        non_diabetic_probability = float(round(probabilities[0] * 100, 2))
        result = 'Positive' if prediction == 1 else 'Negative'

        # Save to DB
        prediction_entry = Prediction(
            user_id=session['user_id'],
            pregnancies=inputs['Pregnancies'],
            glucose=inputs['Glucose'],
            blood_pressure=inputs['BloodPressure'],
            skin_thickness=inputs['SkinThickness'],
            insulin=inputs['Insulin'],
            bmi=inputs['BMI'],
            dpf=inputs['DiabetesPedigreeFunction'],
            age=inputs['Age'],
            result=result,
            diabetic_probability=diabetic_probability,
            non_diabetic_probability=non_diabetic_probability
        )
        db.session.add(prediction_entry)
        db.session.commit()

        # Show message
        flash(
            "Don't worry, early detection helps! Consult a doctor for better management."
            if result == 'Positive' else
            "Great! Keep maintaining a healthy lifestyle.",
            'success'
        )

        return render_template(
                'result.html',
                result=result,
                confidence=diabetic_probability,  # this is for "Model Confidence"
                diabetic_probability=diabetic_probability,
                non_diabetic_probability=non_diabetic_probability,
                prediction_id=prediction_entry.id  # ✅ Not prediction.id!
)

    return render_template('predict.html')



@app.route('/history')
def history():
    if 'user_id' not in session:
        flash('Please log in to view your prediction history.', 'warning')
        return redirect(url_for('login'))

    user_predictions = Prediction.query.filter_by(user_id=session['user_id']).order_by(Prediction.id.desc()).all()
    return render_template('history.html', predictions=user_predictions)



# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

# Home Route


faq_responses = {
    "what is diabetes": "Diabetes is a chronic disease that occurs when blood glucose levels are too high.",
    "what are the symptoms of diabetes": "Common symptoms include frequent urination, excessive thirst, fatigue, blurred vision, and unexplained weight loss.",
    "how can I prevent diabetes": "You can reduce your risk by maintaining a healthy diet, exercising regularly, and keeping your weight under control.",
    "what foods should diabetics avoid": "Diabetics should avoid sugary drinks, white bread, processed snacks, and foods high in saturated fats.",
    "what foods are good for diabetics": "A healthy diabetic diet includes whole grains, leafy greens, lean proteins, nuts, and healthy fats like avocado and olive oil.",
    "is diabetes curable": "Currently, diabetes has no cure, but it can be managed through medication, diet, and lifestyle changes.",
    "how does exercise help diabetes": "Exercise helps lower blood sugar levels, improves insulin sensitivity, and helps with weight management.",
    "can stress cause diabetes": "Stress itself does not cause diabetes, but it can contribute to high blood sugar levels and unhealthy habits.",
    "what is the best exercise for diabetics": "Walking, yoga, swimming, and strength training are excellent exercises for managing diabetes.",
    "how often should diabetics check their blood sugar": "Diabetics should check their blood sugar levels at least once or twice a day, or as recommended by their doctor.",
}

# Custom chatbot responses for general topics
responses = {
    "diabetes": [
        "Diabetes is a chronic condition that affects how your body processes blood sugar.",
        "Managing diabetes includes a healthy diet, regular exercise, and sometimes medication."
    ],
    "diet": [
        "A balanced diet for diabetes includes high fiber, low sugar, and controlled carbohydrates.",
        "Avoid processed sugars and opt for whole grains and lean proteins."
    ],
    "exercise": [
        "Regular physical activity like walking, yoga, and cardio can help manage diabetes.",
        "30 minutes of moderate exercise daily can significantly improve insulin sensitivity."
    ],
    "symptoms": [
        "Common diabetes symptoms include frequent urination, excessive thirst, and sudden weight loss.",
        "If you experience blurred vision or extreme fatigue, consult a doctor."
    ],
    "treatment": [
        "Diabetes treatment may include insulin, oral medication, and lifestyle changes.",
        "Consult your doctor to determine the best treatment plan for your condition."
    ],
    "greeting": [
        "Hello! How can I assist you with diabetes-related questions?",
        "Hi there! Feel free to ask me anything about health and wellness."
    ],
    "default": [
        "I'm sorry, I don't have information on that. Could you ask about diabetes, diet, or exercise?",
        "I'm here to helpp with diabetes and health-related questions!"
    ]
}

# Function to process user input
from nltk.tokenize import word_tokenize

import random

import random

def get_chatbot_response(user_input):
    user_input = user_input.lower().strip()  # Convert to lowercase and remove spaces

    # Check if input matches an FAQ question
    for question, answer in faq_responses.items():
        if question in user_input:
            return answer  # Return exact match from FAQ

    # Handle greetings separately
    greeting_keywords = ["hi", "hello", "hey"]
    if any(word in user_input.split() for word in greeting_keywords):
        return random.choice(responses["greeting"])  # Return a random greeting response

    # Check keyword responses
    for keyword, response_list in responses.items():
        if keyword in user_input:  # Match user input with predefined keywords
            return random.choice(response_list)  

    return random.choice(responses["default"])  # Default response





@app.route('/')
def home():
    return render_template('login.html')

@app.route('/index')
def index():
    user_name = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user_name = user.name
    return render_template('index.html', user_name=user_name)


@app.route('/chatbot', methods=['POST'])
def chatbot():
    user_message = request.json.get("message", "").strip()
    
    if not user_message:
        return jsonify({"response": "Please enter a valid question."})
    
    bot_reply = get_chatbot_response(user_message)
    
    return jsonify({"response": bot_reply})

from xhtml2pdf import pisa
from flask import make_response
import io
from datetime import datetime

@app.route('/download_report/<int:prediction_id>')
def download_report(prediction_id):
    if 'user_id' not in session:
        flash("Please log in to download your report.", "warning")
        return redirect(url_for('login'))

    prediction = Prediction.query.get_or_404(prediction_id)

    if prediction.user_id != session['user_id']:
        flash("Access denied to this report.", "danger")
        return redirect(url_for('dashboard'))  # or your own page

    # Render the report template
    html = render_template("report_template.html", prediction=prediction, now=datetime.now().strftime("%Y-%m-%d %H:%M"))

    # Convert HTML to PDF
    pdf_buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(io.StringIO(html), dest=pdf_buffer)

    if pisa_status.err:
        return f"PDF generation failed: {pisa_status.err}"

    response = make_response(pdf_buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=diabetes_report_{prediction_id}.pdf'
    return response



import plotly.graph_objs as go
import pandas as pd

@app.route('/view_history')
def view_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    predictions = Prediction.query.filter_by(user_id=session['user_id']).order_by(Prediction.timestamp.desc()).all()

    labels = [p.timestamp.strftime('%Y-%m-%d') if p.timestamp else '' for p in predictions]
    glucose_values = [p.glucose for p in predictions]
    bmi_values = [p.bmi for p in predictions]
    diabetic_probs = [p.diabetic_probability for p in predictions]

    return render_template("history.html",
        predictions=predictions,
        labels=labels,
        glucose=glucose_values,
        bmi=bmi_values,
        prob=diabetic_probs
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  
app.run(debug=True)
