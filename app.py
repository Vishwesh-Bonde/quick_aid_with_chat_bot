from flask import Flask, render_template, request, redirect, flash, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

# === DATABASE CONNECTION ===
def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

# === INITIALIZE DATABASE (Users, Remedies, Exercises) ===
def init_db():
    with get_db_connection() as conn:
        cur = conn.cursor()

        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        age INTEGER,
                        gender TEXT,
                        height_cm REAL,
                        weight_kg REAL,
                        blood_group TEXT)''')

        cur.execute('''CREATE TABLE IF NOT EXISTS remedies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        symptom TEXT NOT NULL,
                        remedy TEXT NOT NULL)''')

        cur.execute('''CREATE TABLE IF NOT EXISTS exercises (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        condition TEXT NOT NULL,
                        exercise TEXT NOT NULL)''')

        conn.commit()

# === LOGIN REQUIRED DECORATOR ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to use this feature.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# === ROUTES ===

@app.route('/')
def home():
    user = None
    if 'user_id' in session:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
            user = cur.fetchone()
    return render_template('index.html', username=session.get('username'), user=user)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/home-remedies')
def home_remedies():
    query = request.args.get("query", "").strip().lower()
    result = None

    if query:
        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT symptom, remedy FROM remedies WHERE LOWER(symptom) LIKE ?", (f'%{query}%',))
            result = cur.fetchone()

    return render_template('homeRemedies.html',
                           search_query=query if query else None,
                           search_result=result)

@app.route('/physiotherapy')
def physiotherapy():
    return render_template('physiotherapy.html')

@app.route('/search_exercises')
def search_exercises():
    query = request.args.get("query", "").strip().lower()

    if not query:
        return jsonify([])

    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT condition, exercise FROM exercises WHERE LOWER(condition) LIKE ?", (f'%{query}%',))
        rows = cur.fetchall()

    # ✅ Remove duplicates before sending to frontend
    unique_results = list({(row['condition'], row['exercise']) for row in rows})

    return jsonify(unique_results)

@app.route('/providing-nurse')
@login_required
def providing_nurse():
    return render_template('providingNurse.html')

@app.route('/nearest-doctor')
@login_required
def nearest_doctor():
    return render_template('nearestDr.html')

@app.route('/online-appointment')
@login_required
def online_appointment():
    return render_template('onlineAppointment.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])

@app.route('/api/news')
def get_news():
    API_KEY = 'pub_7885866698dacc1c0a23c8a995c27cb96fb4a'
    try:
        response = requests.get(
            f'https://newsdata.io/api/1/news?apikey={API_KEY}&category=health&language=en',
            timeout=10
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {'error': str(e)}, 500

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    with get_db_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user = cur.fetchone()

        if request.method == 'POST':
            age = request.form['age']
            gender = request.form['gender']
            height_cm = request.form['height']
            weight_kg = request.form['weight']
            blood_group = request.form['blood_group']

            cur.execute('''UPDATE users SET age = ?, gender = ?, height_cm = ?, weight_kg = ?, blood_group = ?
                           WHERE id = ?''', (age, gender, height_cm, weight_kg, blood_group, session['user_id']))
            conn.commit()
            flash('Medical information updated!', 'success')
            return redirect(url_for('home'))

    return render_template('profile.html', user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not username or not email or not password:
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        with get_db_connection() as conn:
            cur = conn.cursor()
            try:
                cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                            (username, email, hashed_password))
                conn.commit()
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email already registered. Try a different one.', 'error')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            flash('Both email and password are required!', 'error')
            return redirect(url_for('login'))

        with get_db_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, username, password FROM users WHERE email = ?", (email,))
            user = cur.fetchone()

            if user and check_password_hash(user['password'], password):
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                flash(f'Welcome, {user["username"]}!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid email or password. Try again.', 'error')

    return render_template('login.html')
@app.route('/services')
def services():
    return render_template('services.html')
@app.route('/faq')
def faq():
    return render_template('faq.html')
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Retrieve form data
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Here you can process the data (e.g., send an email, save to a database)
        # For now, let's just flash a success message
        flash('Your message has been sent successfully!', 'success')

        # Redirect to the home page after submitting
        return redirect(url_for('home'))

    return render_template('contact.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
