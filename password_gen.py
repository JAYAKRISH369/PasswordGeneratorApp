from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from pymongo import MongoClient
from config import Config
import string
import hashlib
import random

# Define Blueprint and DB connection
generate_bp = Blueprint('generate', __name__)
client = MongoClient(Config.MONGO_URI)
db = client.passwordApp

# --- Original Basic Password Logic ---
def generate_password_logic(name, key, part1, part2):
    s = name + part1 + part2
    str_set = set(s)
    common_count = len(s) - len(str_set)
    value = len(name) - common_count

    symbols = {1: "!", 2: "@", 3: "#", 4: "$", 5: "%", 6: "^", 7: "&", 8: "*", 9: "(", 0: ")"}
    upper = chr(ord(name[0]) + value)
    special = str(value) + str(len(name)) + str(value + len(name)) + upper.upper() + symbols.get(value % 10, '!')

    password = ""
    y = u = 0
    while y < len(special) and u < len(key):
        password += special[y] + chr(ord(key[u]) + value)
        y += 1
        u += 1
    while y < len(special):
        password += special[y]
        y += 1
    while u < len(key):
        password += chr(ord(key[u]) + value)
        u += 1

    return password

# --- Enhanced Password Logic ---
def enhanced_password_logic(name, key, counter=1, length=16, use_lower=True, use_upper=True,
                            use_digits=True, use_symbols=True, use_emojis=False, complexity=1, custom_salt=''):
    print("Enhanced Password Logic Parameters:  ")
    charset = ''
    if use_lower:
        charset += string.ascii_lowercase
    if use_upper:
        charset += string.ascii_uppercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()-_=+[]{}|;:,.<>?/"

    emoji_set = "🚀✨🔥💡🎯🛡️💻📱🔐🎉"
    if use_emojis:
        charset += emoji_set

    if not charset:
        return "Error: No charset selected"

    base = f"{name}{key}{counter}{custom_salt}"
    hash_digest = hashlib.sha256(base.encode()).hexdigest()

    password = ''
    for i in range(length):
        index = int(hash_digest[i % len(hash_digest)], 16)
        password += random.choice(charset)

    # Complexity enhancement
    if complexity > 1:
        if use_lower:
            password = insert_random(password, random.choice(string.ascii_lowercase))
        if use_upper:
            password = insert_random(password, random.choice(string.ascii_uppercase))
        if use_digits:
            password = insert_random(password, random.choice(string.digits))
        if use_symbols:
            password = insert_random(password, random.choice("!@#$%^&*"))
        if use_emojis:
            password = insert_random(password, random.choice(emoji_set))

    return password

def insert_random(password, char):
    idx = random.randint(0, len(password) - 1)
    return password[:idx] + char + password[idx+1:]

# --- Combined Route for Basic and Enhanced ---
@generate_bp.route('/', methods=['GET', 'POST'])
@login_required
def generate_password_view():
    result = ''
    mode = 'basic'

    if request.method == 'POST':
        name = request.form['name']
        key = request.form['key']
        mode = request.form.get('mode', 'basic')  # default to basic

        user = db.users.find_one({'_id': current_user.id})
        print('name:', name)
        print('key:', key)
        print('User ID:', current_user.id)
        print('User Value is:', user)

        if mode == 'basic':
            if not user or 'part1' not in user or 'part2' not in user:
                flash("Your profile is incomplete. Please complete it first.")
                return redirect(url_for('google.complete_profile'))
            result = generate_password_logic(name, key, user['part1'], user['part2'])

        else:
            # Get enhanced params
            length = int(request.form.get('length', 16))
            counter = int(request.form.get('counter', 1))
            custom_salt = request.form.get('custom_salt', f"{user.get('part1','')}{user.get('part2','')}")

            use_lower = 'use_lower' in request.form
            use_upper = 'use_upper' in request.form
            use_digits = 'use_digits' in request.form
            use_symbols = 'use_symbols' in request.form
            use_emojis = 'use_emojis' in request.form
            complexity = int(request.form.get('complexity', 1))

            result = enhanced_password_logic(name, key, counter, length, use_lower, use_upper, use_digits,
                                             use_symbols, use_emojis, complexity, custom_salt)
            
            print("Generated Password:", result)    
    return render_template('generate.html', password=result, mode=mode)
