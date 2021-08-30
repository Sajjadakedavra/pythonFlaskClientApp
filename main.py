from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
from flask_wtf.csrf import CSRFProtect




app = Flask(__name__)

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'your secret key'

#protection against CSRF attacks
csrf = CSRFProtect()
csrf.init_app(app)

#protection for cookies in the app configuration object
app.config.update(
    SESSION_COOKIE_SECURE = True, #Browsers will only send cookies with requests over HTTPS if the cookie is marked “secure”. The application must be served over HTTPS for this to make sense.
    SESSION_COOKIE_HTTPONLY = True  #Browsers will not allow JavaScript access to cookies marked as “HTTP only” for security.
)

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'pb42'
app.config['MYSQL_DB'] = 'pythonlogin'

# Intialize MySQL
mysql = MySQL(app)


# http://localhost:5000/pythonlogin/ - this will be the login page, we need to use both GET and POST requests
@app.route('/pythonlogin/', methods=['GET', 'POST'])
def login():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']

        if username.isalnum() == False:
            msg = 'Char other than Alphabet/Number detected!'
            return render_template('index.html', msg=msg)
        
        password = request.form['password']
        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        #cursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password,))
        #CALLING PROCEDURE INSTEAD OF SQL STATEMENT
        args = [username, password]
        result_args = cursor.callproc('CheckForExistingUser', args)
        #print(result_args[1])
        # Fetch one record and return result
        account = cursor.fetchone()
        cursor.close()  #ADDED TO CHECK - REMOVE IF ERRENOUS
        # If account exists in accounts table in out database
        if account:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            # Redirect to home page
            return redirect(url_for('home'))
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'
    # Show the login form with message (if any)
    return render_template('index.html', msg=msg)



    # http://localhost:5000/python/logout - this will be the logout page
@app.route('/pythonlogin/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))


# http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/pythonlogin/register', methods=['GET', 'POST'])
def register():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])

    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        #cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        #CALLING PROCEDURE INSTEAD OF SQL STATEMENT
        args = [username]
        result_args = cursor.callproc('CheckAccountByUsername', args)
        account = cursor.fetchone()
        cursor.close()  #ADDED TO CHECK - REMOVE IF ERRENOUS
        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            #cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s)', (username, password, email,))
            args = [username, password, email]
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            result_args = cursor.callproc('CreateNewAccount', args)
            mysql.connection.commit()
            cursor.close()  #ADDED TO CHECK - REMOVE IF ERRENOUS
            msg = 'You have successfully registered!'

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            #CALLING PROCEDURE INSTEAD OF SQL STATEMENT
            args = [username, password]
            result_args = cursor.callproc('CheckForExistingUser', args)
            # Fetch one record and return result
            account = cursor.fetchone()
            cursor.close()  #ADDED TO CHECK - REMOVE IF ERRENOUS
            # If account exists in accounts table in out database
            if account:
            # Create session data, we can access this data in other routes
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                # Redirect to home page
                return redirect(url_for('home'))
            
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)




# http://localhost:5000/pythinlogin/home - this will be the home page, only accessible for loggedin users
@app.route('/pythonlogin/home')
def home():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'])
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))




# http://localhost:5000/pythinlogin/profile - this will be the profile page, only accessible for loggedin users
@app.route('/pythonlogin/profile')
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        #cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        args = [session['id']]
        result_args = cursor.callproc('GetAccountById', args)
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


if __name__ == "__main__":
    print('running...')
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=True)
