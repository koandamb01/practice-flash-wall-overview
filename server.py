from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL # import the function connectToMySQL from the file mysqlconnection.py
import re, datetime
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "2pacshakur"

# create a regular expression object that we can use run operations on
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
WORD_SPACE_REGEX = re.compile(r'^[A-Za-z ]+')



@app.route('/')
def home():
    return render_template('index.html', **session)


@app.route('/wall')
def wall():
    if 'user_id' not in session:
        return redirect('/')
    
    # Get the user information from the database
    data = {'id': session['user_id']}
    query = """SELECT users.first_name AS first_name, 
                users2.first_name AS sender_name,  
                messages.id AS message_id, 
                messages.message AS message, 
                messages.sender_id AS sender_id, 
                messages.receiver_id AS receiver_id, messages.created_at AS created_at
                FROM users
                LEFT JOIN messages ON messages.receiver_id = users.id
                LEFT JOIN users AS users2 ON users2.id = messages.sender_id
                WHERE users.id = %(id)s;"""
    mysql = connectToMySQL('login_registration_wall')        
    messages_data = mysql.query_db(query, data)


    # get the user info from the DB
    query = 'SELECT first_name FROM users WHERE id = %(id)s;'
    data = {'id': session['user_id']}
    mysql = connectToMySQL('login_registration_wall')
    user = mysql.query_db(query, data)

    # Get the list of users except the logged in user
    mysql = connectToMySQL('login_registration_wall')
    query = 'SELECT id AS receiver_id, first_name AS receiver_name FROM users WHERE id <> %(id)s;'
    other_users = mysql.query_db(query, data)

    return render_template('wall.html', user=user[0], other_users=other_users, messages_data=messages_data)


@app.route('/send', methods=["POST"])
def send_message():
    # record data from form
    data = {
        'message': request.form['message'],
        'sender_id': session['user_id'],
        'receiver_id': request.form['receiver_id']
    }
    mysql = connectToMySQL('login_registration_wall')
    query = 'INSERT INTO messages (message, sender_id, receiver_id) VALUES (%(message)s, %(sender_id)s, %(receiver_id)s);'
    mysql.query_db(query, data)
    return redirect('/wall')


@app.route('/delete/<id>')
def delete(id):
    if 'user_id' not in session:
        session.clear()
        return redirect('/')

    data = {'id': id}
    mysql = connectToMySQL('login_registration_wall')
    query = 'DELETE FROM messages WHERE id = %(id)s'
    mysql.query_db(query, data)
    return redirect('/wall')


@app.route('/register', methods=["POST"])
def register():
    debug()

    # validattion check for first Name
    if len(request.form['first_name']) == 0:
        flash('*First Name is required', 'first_name')

    # validattion check for first Name
    if len(request.form['last_name']) == 0:
        flash('*Last Name is required', 'last_name')

    # validattion check for email
    if len(request.form['email']) == 0:
        flash('*Email is required', 'email')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash('*Invalid email', 'email')
    else:
        query = 'SELECT * FROM users WHERE email = %(email)s'
        data = {'email': request.form['email'] }
        mysql = connectToMySQL('login_registration_wall')
        result = mysql.query_db(query, data)

    # validation for password
    if len(request.form['password']) == 0:
        flash('*Password is required', 'password')
    elif len(request.form['password']) < 8:
        flash('*Password must be at least 8 characters', 'password')
    elif not re.search('[0-9]', request.form['password']):
        flash('*Password must have at leat one number', 'password')
    elif not re.search('[A-Z]', request.form['password']):
        flash('*Password must have at least one Caplital letter', 'password')
    elif request.form['password'] != request.form['confirm_password']:
        flash('*Password must be match', 'confirm_password')
    

    if '_flashes' in session.keys():
        # pass form data to sessions
        session['first_name'], session['last_name'], session['email']= request.form['first_name'], request.form['last_name'], request.form['email']
        return redirect('/')
    
    else: # No validation error so insert data to the database
        # create an hash password
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        
        # get data from the form
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'].strip().lower() ,
            'password': pw_hash
        }
    
        # connect to my Database and run insert query
        mysql = connectToMySQL('login_registration_wall')
        query = 'INSERT INTO users (first_name, last_name, email,password) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s )'
        
        session['user_id'] = mysql.query_db(query, data)
        return redirect('/wall')

    
    return redirect('/')

@app.route('/logout')
def logou():
    session.clear()
    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    # check if this is a POST request
    if request.method != 'POST':
        session.clear()
        return redirect('/')

    # get the form data
    data = { 'email': request.form['email'].strip().lower() }
    mysql = connectToMySQL('login_registration_wall')
    query = 'SELECT * FROM users WHERE email = %(email)s'
    row = mysql.query_db(query, data)

    if len(row) > 0:
        user = row[0]
        if bcrypt.check_password_hash(user['password'], request.form['password']):
            session['user_id'] = user['id']
            return redirect('/wall')
    
    flash('*Email or password invalid', 'login')
    return redirect('/')


















def debug():
    print("*"*20,"Debuging","*"*20)
    print("Form Inputs: ", request.form)
    print("Sessions: ", session)

if __name__ == '__main__':
    app.run(debug = True)