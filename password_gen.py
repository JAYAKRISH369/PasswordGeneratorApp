from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from pymongo import MongoClient
from config import Config
import string
import hashlib
import uuid

# Define Blueprint and DB connection
generate_bp = Blueprint('generate', __name__)
client = MongoClient(Config.MONGO_URI)
db = client.passwordApp
entries = db.password_entries

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
def enhanced_password_logic(name, key, part1, part2, counter=1, length=16, use_lower=True,
                            use_upper=True, use_digits=True, use_symbols=True, use_emojis=False,
                            complexity=1, custom_salt=''):
    groups = []
    if use_lower:
        groups.append(string.ascii_lowercase)
    if use_upper:
        groups.append(string.ascii_uppercase)
    if use_digits:
        groups.append(string.digits)
    if use_symbols:
        groups.append("!@#$%^&*()-_=+[]{}|;:,.<>?/")

    emoji_set = "🚀✨🔥💡🎯💻📱🔐🎉"
    if use_emojis:
        groups.append(emoji_set)

    if not groups:
        return "Error: No charset selected"
    if length < len(groups):
        return f"Error: length must be at least {len(groups)}"

    salt = f"password-generator:{name}:{part1}:{part2}:{counter}:{custom_salt}".encode()
    charset = ''.join(groups)
    digest = hashlib.pbkdf2_hmac(
        'sha256', key.encode(), salt, 600_000, dklen=max(32, length * 2)
    )

    password = [group[digest[index] % len(group)] for index, group in enumerate(groups)]
    for index in range(len(password), length):
        password.append(charset[digest[index] % len(charset)])

    if complexity > 1:
        password.reverse()
    if complexity > 2:
        password = password[::2] + password[1::2]

    return ''.join(password)

# --- Combined Route for Basic and Enhanced ---
@generate_bp.route('/', methods=['GET', 'POST'])
@login_required
def generate_password_view():
    result = ''
    mode = 'basic'
    saved_entries = list(entries.find(
        {'user_id': current_user.id},
        {'_id': 0, 'entry_id': 1, 'name': 1, 'comment': 1}
    ).sort('name', 1))

    if not saved_entries:
        return redirect(url_for('generate.new_entry'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        key = request.form.get('key', '')
        if not name or not key:
            flash('Choose a saved password name and enter a secret key.')
            return render_template('generate.html', password='', mode=mode, saved_entries=saved_entries)
        mode = request.form.get('mode', 'basic')  # default to basic

        user = db.users.find_one({'_id': current_user.id})

        if mode == 'basic':
            if not user or 'part1' not in user or 'part2' not in user:
                flash("Your profile is incomplete. Please complete it first.")
                return redirect(url_for('google.profile'))
            result = generate_password_logic(name, key, user['part1'], user['part2'])

        else:
            # Get enhanced params
            try:
                length = max(10, min(64, int(request.form.get('length') or 16)))
                counter = max(1, int(request.form.get('counter') or 1))
                complexity = max(1, min(3, int(request.form.get('complexity') or 1)))
            except ValueError:
                flash('Length, counter, and complexity must be valid numbers.')
                return render_template('generate.html', password='', mode='enhanced', saved_entries=saved_entries)

            if not user or 'part1' not in user or 'part2' not in user:
                flash("Your profile is incomplete. Please complete it first.")
                return redirect(url_for('google.profile'))
            custom_salt = request.form.get('custom_salt', '').strip()

            use_lower = 'use_lower' in request.form
            use_upper = 'use_upper' in request.form
            use_digits = 'use_digits' in request.form
            use_symbols = 'use_symbols' in request.form
            use_emojis = False

            result = enhanced_password_logic(name, key, user['part1'], user['part2'], counter, length,
                                             use_lower, use_upper, use_digits, use_symbols, use_emojis,
                                             complexity, custom_salt)
            
    return render_template('generate.html', password=result, mode=mode, saved_entries=saved_entries)


@generate_bp.route('/entry/new', methods=['GET', 'POST'])
@login_required
def new_entry():
    name = request.form.get('entry_name', '').strip()
    comment = request.form.get('comment', '').strip()
    if request.method == 'POST' and not name:
        flash('A password name is required.')
        return render_template('new_entry.html')

    if request.method == 'GET':
        return render_template('new_entry.html')

    entries.update_one(
        {'user_id': current_user.id, 'name': name},
        {'$set': {'comment': comment}},
        upsert=True
    )
    entries.update_one(
        {'user_id': current_user.id, 'name': name, 'entry_id': {'$exists': False}},
        {'$set': {'entry_id': uuid.uuid4().hex}}
    )
    flash(f'Saved password name: {name}')
    return redirect(url_for('generate.generate_password_view'))


@generate_bp.route('/entry/<entry_id>/delete', methods=['POST'])
@login_required
def delete_entry(entry_id):
    entries.delete_one({'user_id': current_user.id, 'entry_id': entry_id})
    flash('Saved password name deleted.')
    return redirect(url_for('generate.generate_password_view'))
