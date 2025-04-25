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

        if not user:
            flash("아이디 또는 비밀번호가 잘못되었습니다.")
            return render_template('login.html')

        if user['is_locked']:
            flash("이 계정은 잠겨 있습니다. 관리자에게 문의하세요.")
            return render_template('login.html')

        if check_password_hash(user['password'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']

            # 로그인 성공 시 실패 횟수 초기화
            cursor.execute("UPDATE user SET failed_attempts = 0 WHERE id = ?", (user['id'],))
            db.commit()

            flash("로그인 성공")
            return redirect(url_for('dashboard'))
        else:
            # 실패 횟수 증가
            failed_attempts = user['failed_attempts'] + 1
            is_locked = 1 if failed_attempts >= 5 else 0
            cursor.execute("UPDATE user SET failed_attempts = ?, is_locked = ? WHERE id = ?",
                           (failed_attempts, is_locked, user['id']))
            db.commit()

            if is_locked:
                flash("로그인 5회 실패로 계정이 잠겼습니다.")
            else:
                flash(f"비밀번호가 잘못되었습니다. ({failed_attempts}/5)")

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
        bio = sanitize_input(request.form.get('bio', '').strip())
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

@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = sanitize_input(request.form['title']).strip()
        description = sanitize_input(request.form['description']).strip()
        image_url = sanitize_input(request.form['image_url']).strip()
        price_str = request.form['price'].strip()

        if not title or not description or not price_str:
            flash("모든 항목을 입력해야 합니다.")
            return redirect(url_for('new_product'))

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM product WHERE title = ?", (title,))
        if cursor.fetchone():
            flash("같은 이름의 상품이 이미 존재합니다.")
            return redirect(url_for('new_product'))

        if image_url and not re.match(r'^https?://', image_url):
            flash("이미지 URL은 http:// 또는 https://로 시작해야 합니다.")
            return redirect(url_for('new_product'))

        try:
            price = float(price_str)
            if price <= 0 or price > 10000000:
                flash("가격은 0보다 크고 1,000만 이하이어야 합니다.")
                return redirect(url_for('new_product'))
        except ValueError:
            flash("가격은 숫자 형식이어야 합니다.")
            return redirect(url_for('new_product'))

        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, image_url, price, seller_id) VALUES (?, ?, ?, ?, ?, ?)",
            (product_id, title, description, image_url, price, session['user_id'])
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

from time import time

# 사용자별 최근 메시지 타임스탬프 저장용
user_message_times = {}

@socketio.on('send_message')
def handle_send_message_event(data):
    if 'user_id' not in session:
        print("비인증 사용자 메시지 차단됨")
        return  # 인증 안 된 사용자 무시

    user_id = session['user_id']
    now = time()

    user_message_times.setdefault(user_id, [])
    user_message_times[user_id] = [t for t in user_message_times[user_id] if now - t <= 10]

    if len(user_message_times[user_id]) >= 5:
        print("스팸 메시지 차단됨")
        return

    user_message_times[user_id].append(now)

    if not isinstance(data, dict) or 'message' not in data or 'username' not in data:
        print("잘못된 메시지 형식")
        return

    message = data['message']
    username = data['username']

    if not (1 <= len(message) <= 200):
        print("메시지 길이 제한 초과")
        return

    if not re.match(r'^[가-힣a-zA-Z0-9\s.,!?()\[\]\-_:;"\']+$', message):
        print("허용되지 않은 문자 포함")
        return

    clean_message = sanitize_input(message)

    emit('message', {
        'username': sanitize_input(username),
        'message': clean_message
    }, broadcast=True)

if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, ssl_context='adhoc')

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
        receiver_id = request.form.get("receiver_id", "").strip()
        amount_str = request.form.get("amount", "").strip()

        if not receiver_id or not amount_str:
            flash("모든 항목을 입력해주세요.")
            return redirect(url_for("send_money"))

        try:
            amount = float(amount_str)
            if amount <= 0 or amount > 10000000:
                flash("송금 금액은 0보다 크고 1,000만 이하이어야 합니다.")
                return redirect(url_for("send_money"))
        except ValueError:
            flash("금액은 숫자로 입력해주세요.")
            return redirect(url_for("send_money"))

        # 여기에 실제 송금 로직이 들어감
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

    if not product_id:
        flash("상품 ID가 유효하지 않습니다.")
        return redirect(url_for('my_products'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('my_products'))

    if product['seller_id'] != session['user_id']:
        flash("이 상품에 대한 삭제 권한이 없습니다.")
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
    if 'user_id' not in session:
        print("비인증 사용자 1:1 메시지 차단됨")
        return

    required_keys = ['room', 'sender', 'receiver', 'message']
    if not all(k in data for k in required_keys):
        print("메시지 형식 오류")
        return

    message = data['message']
    if not (1 <= len(message) <= 200):
        print("메시지 길이 초과")
        return

    if not re.match(r'^[가-힣a-zA-Z0-9\s.,!?()\[\]\-_:;"\']+$', message):
        print("허용되지 않은 문자 포함")
        return

    clean_message = sanitize_input(message)

    emit('private_message', {
        'sender': sanitize_input(data['sender']),
        'message': clean_message
    }, room=data['room'])

from datetime import datetime
from time import time

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        target_id = sanitize_input(request.form.get('target_id', '').strip())
        reason = sanitize_input(request.form.get('reason', '').strip())

        if not target_id or not reason:
            flash("모든 항목을 입력해주세요.")
            return redirect(url_for('report'))
        if len(target_id) > 64:
            flash("대상 ID는 64자 이하로 입력해주세요.")
            return redirect(url_for('report'))
        if len(reason) > 500:
            flash("신고 사유는 500자 이하로 입력해주세요.")
            return redirect(url_for('report'))

        cursor.execute("""
            SELECT * FROM report
            WHERE reporter_id = ? AND target_id = ?
        """, (user_id, target_id))
        if cursor.fetchone():
            flash("이미 이 대상을 신고하셨습니다.")
            return redirect(url_for('report'))

        cursor.execute("""
            SELECT COUNT(*) FROM report
            WHERE reporter_id = ? AND DATE(created_at) = DATE('now')
        """, (user_id,))
        count_today = cursor.fetchone()[0]
        if count_today >= 5:
            flash("하루 최대 5건의 신고만 가능합니다.")
            return redirect(url_for('report'))

        report_id = str(uuid.uuid4())
        created_at = datetime.utcnow().isoformat()

        cursor.execute("""
            INSERT INTO report (id, reporter_id, target_id, reason, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (report_id, user_id, target_id, reason, created_at))

        db.commit()

        print(f"[신고 로그] {user_id} → {target_id} 이유: {reason}")

        flash("신고가 접수되었습니다.")
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

@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    print("서버 내부 오류 발생:", traceback.format_exc())  # 콘솔/로그에 출력

    # 사용자에게는 단순 메시지만 보여줌
    flash("알 수 없는 오류가 발생했습니다. 관리자에게 문의하세요.")
    return redirect(url_for('index'))

@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    if product['seller_id'] != session['user_id']:
        flash("이 상품에 대한 수정 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = sanitize_input(request.form['title']).strip()
        description = sanitize_input(request.form['description']).strip()
        image_url = sanitize_input(request.form['image_url']).strip()
        price_str = request.form['price'].strip()

        if not title or not description or not price_str:
            flash("모든 항목을 입력해야 합니다.")
            return redirect(url_for('edit_product', product_id=product_id))

        if len(title) > 100 or len(description) > 1000:
            flash("제목은 100자 이하, 설명은 1000자 이하로 입력해주세요.")
            return redirect(url_for('edit_product', product_id=product_id))

        if image_url and not re.match(r'^https?://', image_url):
            flash("이미지 URL은 http:// 또는 https://로 시작해야 합니다.")
            return redirect(url_for('edit_product', product_id=product_id))

        try:
            price = float(price_str)
            if price <= 0 or price > 10000000:
                flash("가격은 0보다 크고 1,000만 이하이어야 합니다.")
                return redirect(url_for('edit_product', product_id=product_id))
        except ValueError:
            flash("가격은 숫자 형식이어야 합니다.")
            return redirect(url_for('edit_product', product_id=product_id))

        cursor.execute(
            "SELECT * FROM product WHERE title = ? AND id != ?",
            (title, product_id)
        )
        if cursor.fetchone():
            flash("같은 이름의 상품이 이미 존재합니다.")
            return redirect(url_for('edit_product', product_id=product_id))

        cursor.execute("""
            UPDATE product
            SET title = ?, description = ?, image_url = ?, price = ?
            WHERE id = ?
        """, (title, description, image_url, price, product_id))

        db.commit()
        flash("상품이 수정되었습니다.")
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)

def validate_product_input(title, description, image_url, price_str):
    errors = []

    title = sanitize_input(title).strip()
    description = sanitize_input(description).strip()
    image_url = sanitize_input(image_url).strip()
    price_str = price_str.strip()

    if not title or len(title) > 100:
        errors.append("제목은 1~100자 사이여야 합니다.")

    if not description or len(description) > 1000:
        errors.append("설명은 1~1000자 사이여야 합니다.")

    try:
        price = float(price_str)
        if price <= 0 or price > 10000000:
            errors.append("가격은 0보다 크고 1,000만 이하이어야 합니다.")
    except ValueError:
        errors.append("가격은 숫자 형식이어야 합니다.")
        price = None

    return errors, title, description, image_url, price
