from flask import Blueprint, redirect, url_for, session, request, render_template, current_app
from flask_login import login_user, UserMixin
from authlib.integrations.flask_client import OAuth
from config import Config
from pymongo import MongoClient
import uuid

google_bp = Blueprint('google', __name__)
oauth = OAuth()


client = MongoClient(Config.MONGO_URI)
db = client.passwordApp
users_col = db.users


class User(UserMixin):
    def __init__(self, data):
        self.id = data['_id']
        self.name = data.get('username') or  data['email'] or data.get('name')
        self.email = data['email']


def register_google_oauth(app):
    oauth.init_app(app)
    oauth.register(
    name='google',
    client_id=Config.GOOGLE_CLIENT_ID,
    client_secret=Config.GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)



@google_bp.route('/login')
def google_login():

    nonce = uuid.uuid4().hex
    session['nonce'] = nonce

    redirect_uri = url_for('google.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)


@google_bp.route('/callback')
def google_callback():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token, nonce=session.get('nonce'))
    print(user_info)
    email = user_info['email']
    name = user_info.get('name', email.split('@')[0])
    user = users_col.find_one({'_id': email})

    if not user:
        name = user_info.get('name', email.split('@')[0])
        users_col.insert_one({
            '_id': email,
            'email': email,
            'name': name,
            'username': name.lower().replace(" ", ""),
            'method': 'google'
        })
        session['email'] = email
        return redirect(url_for('google.complete_profile'))

    user = users_col.find_one({'_id': email})
    login_user(User(user))
    return redirect(url_for('index'))


@google_bp.route('/complete-profile', methods=['GET', 'POST'])
def complete_profile():
    email = session.get('email')
    if not email:
        return redirect('/')

    if request.method == 'POST':
        username = request.form['username']
        part1 = request.form['part1']
        part2 = request.form['part2']

        users_col.update_one(
            {'_id': email},
            {'$set': {
                'username': username,
                'part1': part1,
                'part2': part2
            }}
        )

        user = users_col.find_one({'_id': email})
        login_user(User(user))
        session.pop('email', None)
        return redirect(url_for('index'))

    return render_template('complete_profile.html')
