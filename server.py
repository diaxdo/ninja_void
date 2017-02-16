import os
from flask import Flask, session, render_template, redirect, flash, request
from flask_bcrypt import Bcrypt
from mysqlconnection import MySQLConnector

app = Flask(__name__)
app.secret_key = 'k3y'
bcrypt = Bcrypt(app)
mysql = MySQLConnector(app,'ninja_void')


@app.route('/')
def index():
    if session.has_key('user'):
        return redirect('/wall')
    return render_template('index.html')

@app.route('/process_register', methods=['POST'])
def process():
    user_name = request.form['user_name']
    email = request.form['email']
    password = request.form['password']
    is_username_valid = False
    is_email_valid = False
    is_password_valid = False

    if len(user_name)==0:
        flash('Name cannot be blank', 'registration')
        is_username_valid = False
    else:
        is_username_valid = True

    if len(email)==0:
        flash('Email cannot be blank', 'registration')
        is_email_valid = False
    else:
        is_email_valid = True
    #use regex to confirm the email is valid

    if len(password) < 3:
        flash('Password must be at least three characters','registration')
        is_password_valid = False
    else:
        is_password_valid = True
    if is_username_valid and is_email_valid and is_password_valid:
        print "creating user!!!"
        #save to db
        hashed_pw = bcrypt.generate_password_hash(password)
        query = 'insert into ninja_void.users(user_name, email, password, created_at, updated_at) values(:user_name, :email, :password, NOW(), NOW());'
        data = {
        'user_name': user_name,
        'email': email,
        'password': hashed_pw
        }
        user_id = mysql.query_db(query, data)
        if (user_id) == 0:
            flash('Unexpected error!!')
            redirect('/')

        query = 'select * from users where id= :id'     #after registering, the user is logged in
        data = {'id': user_id}
        results = mysql.query_db(query,data)
        session['user']= results[0]

        print "user logged in!"
        return redirect('/wall')
    else:
        return redirect('/')


@app.route('/process_login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    query = 'select  * from users where email= :email limit 1;' #limit 1 so you get one email in case user has more
    data = {'email': email}
    user = mysql.query_db(query, data)
    if len(user) > 0:
        if bcrypt.check_password_hash(user[0]['password'], password):
            print 'YOU ARE LOGGED IN'
            session['user']= user[0]
            return redirect('/wall')
        else:
            flash('invalid credentials.','login')
            return redirect('/')
    else:
        flash('ur email sux', 'login')
        return redirect('/')

@app.route('/process_logoff', methods=['POST'])              #to log user out we destroy session
def logoff():
    print "about to process logoff"
    if session.has_key('user'):         #check to see if they are logged in before logging out
        session.pop('user')
    return redirect('/')

@app.route('/wall')
def wall():
    if not session.has_key('user'):
        flash('Nice try. You have to be logged in first!', 'logged_off')
        return redirect('/')
    query = 'select users.user_name, messages.id, messages.user_id, messages.message, messages.created_at '
    query += 'from users join messages on messages.user_id = users.id'
    messages = mysql.query_db(query)
    return render_template('wall.html', messages= messages)

@app.route('/process_message', methods=['POST'])
def message():
    if not session.has_key('user'):
        redirect('/')
    if not request.form.has_key('message') or len(request.form['message']) < 2:
        flash('Please type a longer message')
        redirect('/wall')
    query = 'insert into messages(user_id, message, created_at, updated_at)'
    query += 'values(:user_id, :message, NOW(), NOW());'
    data = {
        'user_id' : session['user']['id'],
        'message' : request.form['message']
    }
    message_id = mysql.query_db(query,data)
    if int(message_id) == 0:
        flash('Something went wrong')
    return redirect('/wall')

@app.route('/wall/<message_id>')
def thread(message_id):
    #comments where the comments message id is equal to the id of the message this page is on
    query = 'select users.user_name, comments.comment, comments.created_at, comments.user_id '
    query += 'from comments join users on comments.user_id = users.id where comments.message_id = :message_id'
    data = {
    'message_id' : message_id
    }
    comments = mysql.query_db(query,data)
    print comments
    #selecting the message where the id of message is equal to the page (thread) id = 1 message w/the comments
    query = 'select users.user_name, messages.id, messages.user_id, messages.message, messages.created_at '
    query += 'from messages join users on messages.user_id = users.id where messages.id = :message_id;'
    data = {
    'message_id' : message_id
    }
    message = mysql.query_db(query,data)
    return render_template('thread.html', comments=comments, message=message[0])

@app.route('/process_comment/<message_id>', methods=['POST'])
def comment(message_id):
    if not session.has_key('user'):
        return redirect('/')
    if not request.form.has_key('comment') or len(request.form['comment']) < 2:
        flash('Please type a longer comment')
        return redirect('/wall/{}'.format(message_id))
    query = 'insert into comments(user_id, message_id, comment, created_at, updated_at)'
    query += 'values(:user_id, :message_id, :comment, NOW(), NOW());'
    data = {
        'user_id' : session['user']['id'],
        'comment' : request.form['comment'],
        'message_id': message_id
    }
    comment_id = mysql.query_db(query,data)
    if int(comment_id) == 0:
        flash('Something went wrong')
    return redirect('/wall/{}'.format(message_id))

port = int(os.environ.get('PORT', 5000))
app.run(debug=True, port=port)
