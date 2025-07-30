from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from pymongo import MongoClient
from config import Config

generate_bp = Blueprint('generate', __name__)
client = MongoClient(Config.MONGO_URI)
db = client.passwordApp

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

@generate_bp.route('/', methods=['GET', 'POST'])
@login_required
def generate_password_view():
    result = ''
    if request.method == 'POST':
        name = request.form['name']
        key = request.form['key']
        user = db.users.find_one({'_id': current_user.id})
        print('name:', name)
        print('key:', key)
        print('User ID:', current_user.id)
        print('User Value is:',user)

        # if not user or 'part1' not in user or 'part2' not in user:
        #     flash("Your profile is incomplete. Please complete it first.")
        #     return redirect(url_for('google.complete_profile'))
        
        result = generate_password_logic(name, key, user['part1'], user['part2'])
        # return render_template('index.html', result=result, user=current_user)
    return render_template('generate.html', password=result)
