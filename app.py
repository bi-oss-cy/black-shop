from flask import Flask, render_template_string, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'secretkey123'

# DB 초기화 함수 (최초 1회 실행)
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

@app.route('/')
def home():
    if 'username' in session:
        return redirect('/dashboard')
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return 'Username already exists!'
        conn.close()
        return redirect('/login')
    return render_template_string(register_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        conn.close()
        if row and check_password_hash(row[0], password):
            session['username'] = username
            return redirect('/dashboard')
        else:
            return 'Invalid credentials!'
    return render_template_string(login_template)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template_string(dashboard_template, username=session['username'])
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

# HTML 템플릿
register_template = """
<!DOCTYPE html>
<html><body>
<h2>Register</h2>
<form method="post">
  Username: <input type="text" name="username" required><br>
  Password: <input type="password" name="password" required><br>
  <input type="submit" value="Register">
</form>
<a href="/login">Already have an account?</a>
</body></html>
"""

login_template = """
<!DOCTYPE html>
<html><body>
<h2>Login</h2>
<form method="post">
  Username: <input type="text" name="username" required><br>
  Password: <input type="password" name="password" required><br>
  <input type="submit" value="Login">
</form>
<a href="/register">Don't have an account?</a>
</body></html>
"""

dashboard_template = """
<!DOCTYPE html>
<html><body>
<h2>Welcome, {{ username }}!</h2>
<p>You are now logged in.</p>
<a href="/logout">Logout</a>
</body></html>
"""

if __name__ == '__main__':
    init_db()
    import os
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
