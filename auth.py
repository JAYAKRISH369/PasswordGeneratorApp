from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import UserMixin, login_user
from werkzeug.security import generate_password_hash, check_password_hash

auth_bp = Blueprint('auth', __name__)

class User(UserMixin):
    def __init__(self, data):
        self.id = data.get('_id') or data.get('email')  # 'sub' is Google's unique user ID
        self.name = data.get('name') or data.get('username') or data['email'].split('@')[0]  # fallback to email
        self.email = data.get('email')

def load_user(user_id, db):
    data = db.users.find_one({'_id': user_id})
    return User(data) if data else None

def get_db():
    from app import db
    return db

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    db = get_db()
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        part1 = request.form['part1']
        part2 = request.form['part2']

        if db.users.find_one({'_id': email}):
            flash("Email already registered")
            return redirect(url_for('auth.register'))

        db.users.insert_one({
            '_id': email,
            'email': email,
            'username': username,
            'password': password,
            'method': 'manual',
            'part1': part1,
            'part2': part2
        })
        flash("Registered successfully. Please log in.")
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = db.users.find_one({'_id': email, 'method': 'manual'})

        if user and check_password_hash(user['password'], password):
            login_user(User(user))
            return redirect(url_for('index'))
        else:
            flash("Invalid credentials.")
    return render_template('login.html')


@auth_bp.route("/callback")
def callback():
    try:
        # Get authorization code Google sent back
        code = request.args.get("code")
        if not code:
            return redirect(url_for("error_page"))

        # Get token
        token = google.authorize_access_token()
        resp = google.get("userinfo")
        user_info = resp.json()

        if not user_info or "email" not in user_info:
            return redirect(url_for("error_page"))

        # Optional: Check required keys like 'username'
        if 'username' not in user_info:
            return redirect(url_for("error_page"))

        # Store in session
        session["user"] = {
            "username": user_info["name"],  # or 'username' if available
            "email": user_info["email"]
        }

        return redirect(url_for("home"))

    except Exception as e:
        print("OAuth error:", e)
        return redirect(url_for("error_page"))

