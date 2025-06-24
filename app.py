from flask import Flask, render_template_string, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os

app = Flask(__name__)
app.secret_key = 'secretkey123'

# DB 초기화 함수
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

# 템플릿
register_template = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>회원가입</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-white d-flex justify-content-center align-items-center vh-100">
  <div class="card bg-secondary p-4">
    <h2 class="mb-3">회원가입</h2>
    <form method="post">
      <input type="text" name="username" class="form-control mb-2" placeholder="아이디" required>
      <input type="password" name="password" class="form-control mb-3" placeholder="비밀번호" required>
      <button class="btn btn-primary w-100" type="submit">회원가입</button>
    </form>
    <a class="text-white mt-2" href="/login">계정이 있으신가요?</a>
  </div>
</body>
</html>
"""

login_template = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>로그인</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-white d-flex justify-content-center align-items-center vh-100">
  <div class="card bg-secondary p-4">
    <h2 class="mb-3">로그인</h2>
    <form method="post">
      <input type="text" name="username" class="form-control mb-2" placeholder="아이디" required>
      <input type="password" name="password" class="form-control mb-3" placeholder="비밀번호" required>
      <button class="btn btn-success w-100" type="submit">로그인</button>
    </form>
    <a class="text-white mt-2" href="/register">계정이 없으신가요?</a>
  </div>
</body>
</html>
"""

dashboard_template = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>대시보드</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark text-white text-center d-flex flex-column justify-content-center align-items-center vh-100">
  <h2>환영합니다, {{ username }}!</h2>
  <p>성공적으로 로그인되었습니다.</p>
  <a class="btn btn-outline-light mt-3" href="/logout">로그아웃</a>
</body>
</html>
"""

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
