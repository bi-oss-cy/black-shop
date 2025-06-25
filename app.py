rom flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'secretkey123'

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL
    )''')
    conn.commit()
    conn.close()

@app.before_first_request
def initialize():
    init_db()
    create_admin_user()

def create_admin_user():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # 관리자 계정이 없으면 생성
    c.execute('SELECT * FROM users WHERE username = ?', ('fjfj3521',))
    if not c.fetchone():
        from werkzeug.security import generate_password_hash
        pw_hash = generate_password_hash('aa4746')
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('fjfj3521', pw_hash))
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
    return render_template('register.html')

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
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect('/login')

@app.route('/products')
def products():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM products')
    products_list = c.fetchall()
    conn.close()
    return render_template('products.html', products=products_list)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = c.fetchone()
    conn.close()
    if not product:
        return "Product not found", 404
    return render_template('product_detail.html', product=product)

@app.route('/cart')
def cart():
    cart = session.get('cart', {})
    product_ids = list(cart.keys())
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    products_in_cart = []
    for pid in product_ids:
        c.execute('SELECT * FROM products WHERE id = ?', (pid,))
        p = c.fetchone()
        if p:
            products_in_cart.append((p, cart[pid]))
    conn.close()
    return render_template('cart.html', products=products_in_cart)

@app.route('/cart/add/<int:product_id>')
def add_to_cart(product_id):
    cart = session.get('cart', {})
    cart[str(product_id)] = cart.get(str(product_id), 0) + 1
    session['cart'] = cart
    return redirect('/cart')

@app.route('/cart/remove/<int:product_id>')
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    cart.pop(str(product_id), None)
    session['cart'] = cart
    return redirect('/cart')

@app.route('/checkout')
def checkout():
    # 결제 시뮬레이션
    session.pop('cart', None)
    return render_template('checkout.html')

# 관리자 로그인 분리
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'fjfj3521':
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('SELECT password FROM users WHERE username = ?', (username,))
            row = c.fetchone()
            conn.close()
            if row and check_password_hash(row[0], password):
                session['admin'] = True
                return redirect('/admin/products')
            else:
                return 'Invalid admin credentials!'
        else:
            return 'Invalid admin credentials!'
    return render_template('admin_login.html')

@app.route('/admin/products')
def admin_products():
    if not session.get('admin'):
        return redirect('/admin/login')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM products')
    products_list = c.fetchall()
    conn.close()
    return render_template('admin_products.html', products=products_list)

@app.route('/admin/products/add', methods=['GET', 'POST'])
def admin_add_product():
    if not session.get('admin'):
        return redirect('/admin/login')
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO products (name, description, price) VALUES (?, ?, ?)', (name, description, price))
        conn.commit()
        conn.close()
        return redirect('/admin/products')
    return render_template('admin_add_product.html')

@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
def admin_edit_product(product_id):
    if not session.get('admin'):
        return redirect('/admin/login')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        c.execute('UPDATE products SET name=?, description=?, price=? WHERE id=?', (name, description, price, product_id))
        conn.commit()
        conn.close()
        return redirect('/admin/products')
    c.execute('SELECT * FROM products WHERE id=?', (product_id,))
    product = c.fetchone()
    conn.close()
    if not product:
        return "Product not found", 404
    return render_template('admin_edit_product.html', product=product)

@app.route('/admin/products/delete/<int:product_id>')
def admin_delete_product(product_id):
    if not session.get('admin'):
        return redirect('/admin/login')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM products WHERE id=?', (product_id,))
    conn.commit()
    conn.close()
    return redirect('/admin/products')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('admin', None)
    return redirect('/login')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
# app.py 일부 예시
from flask import Flask, render_template, request, redirect, session, url_for

app = Flask(__name__)
app.secret_key = 'secretkey123'

# 상품 목록 임시 데이터 (나중엔 DB 연결 필요)
products = [
    {'id': 1, 'name': '상품 A', 'price': 10000, 'stock': 5, 'description': '상품 A 설명'},
    {'id': 2, 'name': '상품 B', 'price': 20000, 'stock': 10, 'description': '상품 B 설명'},
]

@app.route('/admin')
def admin():
    # 로그인 상태와 관리자 권한 체크 필요
    return render_template('admin.html', products=products)

@app.route('/products')
def products_list():
    return render_template('products.html', products=products)

@app.route('/products/<int:product_id>')
def product_detail(product_id):
    product = next((p for p in products if p['id'] == product_id), None)
    if not product:
        return "상품이 없습니다.", 404
    return render_template('product_detail.html', product=product)

@app.route('/cart')
def cart():
    cart = session.get('cart', [])
    total = sum(item['price'] * item['quantity'] for item in cart)
    return render_template('cart.html', cart=cart, total=total)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    quantity = int(request.form.get('quantity', 1))
    product = next((p for p in products if p['id'] == product_id), None)
    if not product or quantity > product['stock']:
        return "수량이 올바르지 않거나 상품이 없습니다.", 400

    cart = session.get('cart', [])
    for item in cart:
        if item['id'] == product_id:
            item['quantity'] += quantity
            break
    else:
        cart.append({'id': product_id, 'name': product['name'], 'price': product['price'], 'quantity': quantity})
    session['cart'] = cart
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    cart = session.get('cart', [])
    cart = [item for item in cart if item['id'] != product_id]
    session['cart'] = cart
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        # 주문 처리 로직 작성
        session.pop('cart', None)
        return "결제가 완료되었습니다."
    return render_template('checkout.html')
