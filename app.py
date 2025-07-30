from flask import Flask, render_template
from flask_login import LoginManager, login_required, logout_user, current_user
from pymongo import MongoClient
from config import Config
from auth import auth_bp, load_user
from google_auth import google_bp, register_google_oauth
from password_gen import generate_bp
import os

app = Flask(__name__)
app.config.from_object(Config)

register_google_oauth(app)

client = MongoClient(Config.MONGO_URI)
db = client.passwordApp


login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

@login_manager.user_loader
def user_loader(user_id):
    return load_user(user_id, db)



app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(google_bp, url_prefix='/google')
app.register_blueprint(generate_bp, url_prefix='/generate')

@app.route('/')
@login_required
def index():
    print("current User Info:", current_user.id, current_user.name, current_user.email)
    return render_template('index.html', username=current_user.name)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('login.html')

@app.route("/error")
def error_page():
    return render_template("error.html")

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
