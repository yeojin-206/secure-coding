import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
import re
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash,check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)
csrf = CSRFProtect(app)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)#30분 비활동 시 만료


def sanitize_input(s):
    # 모든 HTML 태그 제거_XSS공격 방지용
    return re.sub(r'<.*?>', '', s)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

def is_valid_username(username):
    return re.match(r'^[a-zA-Z0-9_]{4,20}$', username)

def is_valid_password(password):
    return len(password) >= 8 and re.search(r'\d', password) and re.search(r'[A-Z]', password)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not is_valid_username(username):
            flash("아이디는 4~20자의 영문자/숫자/밑줄만 허용됩니다.")
            return redirect(url_for('register'))
        if not is_valid_password(password):
            flash("비밀번호는 8자 이상이며, 숫자와 대문자를 포함해야 합니다.")
            return redirect(url_for('register'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash("이미 존재하는 사용자명입니다.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO user (username, password) VALUES (?, ?)", (username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session.permanent = True  # 세션 타임아웃 적용
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash("로그인 성공")
            return redirect(url_for('dashboard'))
        else:
            flash("아이디 또는 비밀번호가 잘못되었습니다.")
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    # 모든 상품 조회
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()
    return render_template('dashboard.html', products=all_products, user=current_user)

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        bio = request.form.get('bio', '')
        new_password = request.form.get('new_password', '')

        # bio 업데이트
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))

        # 비밀번호 변경 요청이 있으면 업데이트
        if new_password.strip():  # 공백 제외하고 비어있지 않다면
            hashed_pw = generate_password_hash(new_password)
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_pw, session['user_id']))
            flash('비밀번호가 변경되었습니다.')

        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    return render_template('profile.html', user=current_user)

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = sanitize_input(request.form['title'])
        description = sanitize_input(request.form['description'])
        image_url = sanitize_input(request.form['image_url'])
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, image_url, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

@socketio.on('send_message')
def handle_send_message_event(data):
    message = sanitize_input(data['message'])
    username = data.get('username')
    emit('message', {'username': username, 'message': message}, broadcast=True)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)

@app.route("/search")
def search():
    query = request.args.get("query", "").lower()
    if not query:
        return render_template("search.html", results=None)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE LOWER(title) LIKE ?", ('%' + query + '%',))
    results = cursor.fetchall()

    return render_template("search.html", results=results)

@app.route("/send", methods=["GET", "POST"])
def send_money():
    if not session.get('reauthenticated'):
        return redirect(url_for('reauth'))
    if request.method == "POST":
        receiver_id = request.form["receiver_id"]
        amount = request.form["amount"]
        
        print(f"사용자에게 송금: 받는 사람 = {receiver_id}, 금액 = {amount}")

        flash("송금이 완료되었습니다!")
        return redirect(url_for("dashboard"))

    return render_template("send_money.html")

@app.route("/admin")
def admin():
    if not session.get("is_admin"):
        flash("관리자만 접근 가능합니다.")
        return redirect(url_for("dashboard"))
    return render_template("admin.html")

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)

        cursor.execute("SELECT * FROM user WHERE username = 'admin'")
        if not cursor.fetchone():
            admin_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO user (id, username, password, bio, is_admin) VALUES (?, ?, ?, ?, 1)",
                (admin_id, 'admin', 'adminpass', '관리자 계정입니다.')
            )

        db.commit()

@app.route('/myproducts')
def my_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    my_items = cursor.fetchall()

    return render_template('my_products.html', products=my_items)

@app.route('/product/delete/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product or product['seller_id'] != session['user_id']:
        flash("삭제 권한이 없습니다.")
        return redirect(url_for('my_products'))

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("상품이 삭제되었습니다.")
    return redirect(url_for('my_products'))

@app.route('/chat/<target_id>')
def private_chat(target_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
    target_user = cursor.fetchone()
    if not target_user:
        flash("대상을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))
    return render_template('private_chat.html', target_id=target_id, target_username=target_user['username'])
@socketio.on('join_room')
def handle_join_room(data):
    join_room(data['room'])

@socketio.on('private_message')
def handle_private_message(data):
    message = sanitize_input(data['message'])
    room = data['room']
    sender = data['sender']
    emit('private_message', {'sender': sender, 'message': message}, room=room)


@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = sanitize_input(request.form['reason'])
        db = get_db()
        cursor = db.cursor()
        report_id = str(uuid.uuid4())

        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )

        # 상품 신고 누적 3건 이상이면 차단
        cursor.execute("SELECT COUNT(*) FROM report WHERE target_id = ?", (target_id,))
        report_count = cursor.fetchone()[0]

        # 상품 차단
        cursor.execute("UPDATE product SET is_blocked = 1 WHERE id = ? AND ? >= 3", (target_id, report_count))
        
        # 사용자 차단
        cursor.execute("UPDATE user SET is_dormant = 1 WHERE id = ? AND ? >= 5", (target_id, report_count))

        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')

@app.route('/reauth', methods=['GET', 'POST'])
def reauth():
    if request.method == 'POST':
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            session['reauthenticated'] = True
            return redirect(url_for('change_password'))
        else:
            flash("비밀번호가 일치하지 않습니다.")
    return render_template('reauth.html')
