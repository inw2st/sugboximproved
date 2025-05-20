from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify
from datetime import datetime, timedelta
import sqlite3
import requests  # 미사용이지만 유지
import secrets
import hashlib
import os
from flask_talisman import Talisman

app = Flask(__name__)
if os.environ.get('FLASK_ENV') != 'development':
    Talisman(app,
             force_https=True,
             content_security_policy=None,
             strict_transport_security=True,
             strict_transport_security_preload=True,
             session_cookie_secure=True)
else:
    app.debug = True

app.secret_key = secrets.token_hex(32)


def init_db():
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    
    # 기존 테이블 확인
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='suggestions'")
    table_exists = c.fetchone() is not None
    
    if table_exists:
        # 기존 테이블 구조 확인
        c.execute("PRAGMA table_info(suggestions)")
        columns = [column[1] for column in c.fetchall()]
        
        # 필요한 컬럼 추가
        try:
            if 'ip_address' not in columns:
                c.execute('ALTER TABLE suggestions ADD COLUMN ip_address TEXT')
                print("ip_address 컬럼 추가됨")
                
            if 'user_agent' not in columns:
                c.execute('ALTER TABLE suggestions ADD COLUMN user_agent TEXT')
                print("user_agent 컬럼 추가됨")
                
            if 'timestamp' not in columns:
                c.execute('ALTER TABLE suggestions ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP')
                print("timestamp 컬럼 추가됨")
        except sqlite3.OperationalError as e:
            print(f"데이터베이스 업데이트 중 오류 발생: {e}")
    else:
        # 테이블이 없으면 새로 생성
        c.execute('''CREATE TABLE suggestions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    grade TEXT NOT NULL,
                    content TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
        print("suggestions 테이블 생성됨")
    
    # 관리자 테이블 확인 및 생성
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admin'")
    admin_exists = c.fetchone() is not None
    
    if not admin_exists:
        c.execute('''CREATE TABLE admin (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    remember_token TEXT
                )''')
        print("admin 테이블 생성됨")
        
    # 기본 관리자 계정 추가
    hashed_password = hashlib.sha256('admin123'.encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO admin (username, password) VALUES (?, ?)", ('admin', hashed_password))
    
    conn.commit()
    conn.close()
    print("데이터베이스 초기화 완료")


def can_submit(request):
    user_ip = request.remote_addr
    if user_ip == '210.100.145.92':
        return True

    last_submit = request.cookies.get('last_submit')
    if last_submit:
        try:
            last_time = datetime.strptime(last_submit, '%Y-%m-%d')
            if last_time.date() == datetime.now().date():
                return False
        except ValueError:
            pass
    return True


def check_remember_token():
    if 'admin' in session:
        return
    token = request.cookies.get('remember_token')
    if token:
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT username FROM admin WHERE remember_token=?', (token,))
        admin = c.fetchone()
        conn.close()
        if admin:
            session['admin'] = admin[0]


@app.before_request
def auto_login():
    if 'admin' in session:
        return
    token = request.cookies.get('remember_token')
    if token:
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT username FROM admin WHERE remember_token=?', (token,))
        admin = c.fetchone()
        conn.close()
        if admin:
            session['admin'] = admin[0]


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return '잘못된 요청입니다.', 400

        grade = data.get('grade')
        content = data.get('content')

        if not grade or not content:
            return '모든 항목을 입력해주세요.', 400

        if not can_submit(request):
            return '오늘은 이미 건의사항을 제출하셨습니다.', 403

        # IP와 User-Agent 정보 수집
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '알 수 없음')

        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        
        # 테이블 구조 확인
        c.execute("PRAGMA table_info(suggestions)")
        columns = [column[1] for column in c.fetchall()]
        
        # 컬럼 존재 여부에 따라 쿼리 분기
        if 'ip_address' in columns and 'user_agent' in columns:
            c.execute('INSERT INTO suggestions (grade, content, ip_address, user_agent) VALUES (?, ?, ?, ?)', 
                      (grade, content, ip_address, user_agent))
        else:
            c.execute('INSERT INTO suggestions (grade, content) VALUES (?, ?)', (grade, content))
            
        suggestion_id = c.lastrowid
        conn.commit()
        conn.close()

        response = make_response(jsonify({'id': suggestion_id}))
        response.set_cookie('last_submit', datetime.now().strftime('%Y-%m-%d'), max_age=86400, httponly=True)
        return response

    # GET 요청 시 캐시 방지 헤더 설정
    html = render_template('index.html')
    response = make_response(html)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route('/delete_suggestions', methods=['POST'])
def delete_suggestions():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    delete_ids = request.form.getlist('delete_ids')
    if delete_ids:
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        placeholders = ','.join(['?'] * len(delete_ids))
        query = f"DELETE FROM suggestions WHERE id IN ({placeholders})"
        c.execute(query, delete_ids)
        conn.commit()
        conn.close()

    return redirect(url_for('admin_panel'))


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET' and 'remember_token' in request.cookies and 'admin' not in session:
        token = request.cookies.get('remember_token')
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT username FROM admin WHERE remember_token=?', (token,))
        admin = c.fetchone()
        conn.close()

        if admin:
            session['admin'] = admin[0]
            return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            error_msg = "아이디와 비밀번호를 모두 입력해주세요."
            return render_template('admin_login.html', error=error_msg)

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT * FROM admin WHERE username=? AND password=?', (username, hashed_password))
        admin = c.fetchone()

        if admin:
            session.permanent = True
            session['admin'] = username

            # 항상 remember_token 생성
            remember_token = secrets.token_hex(32)
            c.execute('UPDATE admin SET remember_token=? WHERE username=?', (remember_token, username))
            conn.commit()

            response = make_response(redirect(url_for('index')))
            response.set_cookie(
                'remember_token',
                remember_token,
                max_age=30 * 24 * 60 * 60,
                httponly=True,
                secure=True if os.environ.get('FLASK_ENV') != 'development' else False
            )
            
            conn.close()
            return response
        else:
            conn.close()
            error_msg = "로그인에 실패했습니다. 아이디와 비밀번호를 확인해주세요."
            return render_template('admin_login.html', error=error_msg)

    return render_template('admin_login.html')


@app.route('/admin/panel', methods=['GET'])
def admin_panel():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    
    # 테이블 구조 확인
    c.execute("PRAGMA table_info(suggestions)")
    columns = [column[1] for column in c.fetchall()]
    
    # 필요한 모든 컬럼 존재 여부 확인
    has_ip = 'ip_address' in columns
    has_user_agent = 'user_agent' in columns
    has_timestamp = 'timestamp' in columns
    
    # 동적으로 쿼리 구성
    query = 'SELECT id, grade, content'
    
    if has_ip:
        query += ', ip_address'
    else:
        query += ', NULL as ip_address'
        
    if has_user_agent:
        query += ', user_agent'
    else:
        query += ', NULL as user_agent'
        
    if has_timestamp:
        query += ', timestamp'
    else:
        query += ', NULL as timestamp'
        
    query += ' FROM suggestions ORDER BY '
    query += 'timestamp DESC' if has_timestamp else 'id DESC'
    
    c.execute(query)
    suggestions = c.fetchall()
    conn.close()
    
    # 템플릿에 데이터 전달
    return render_template('admin_panel.html', suggestions=suggestions)


@app.route('/logout')
def logout():
    if 'admin' in session:
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('UPDATE admin SET remember_token=NULL WHERE username=?', (session['admin'],))
        conn.commit()
        conn.close()

    session.pop('admin', None)
    response = make_response(redirect(url_for('index')))
    response.delete_cookie('remember_token')
    return response


if __name__ == '__main__':
    init_db()
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='127.0.0.1', port=8000, debug=debug_mode)