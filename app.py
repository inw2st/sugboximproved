from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify
from datetime import datetime, timedelta
import sqlite3
import requests
import secrets
import hashlib
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

RECAPTCHA_SITE_KEY = '6LfI9T8rAAAAAL7SyauFEUe1yxmfnA5mITgA3IaY'
RECAPTCHA_SECRET_KEY = '6LfI9T8rAAAAAE03-RWbbbZk5haE_R8O3KZb_LTx'

def init_db():
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS suggestions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    grade TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS admin (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    remember_token TEXT
                )''')
    hashed_password = hashlib.sha256('admin123'.encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO admin (username, password) VALUES (?, ?)", ('admin', hashed_password))
    conn.commit()
    conn.close()

def can_submit(request):
    user_ip = request.remote_addr
    if user_ip == '127.0.0.1':
        return True
    
    last_submit = request.cookies.get('last_submit')
    if last_submit:
        last_time = datetime.strptime(last_submit, '%Y-%m-%d')
        if last_time.date() == datetime.now().date():
            return False
    return True

def verify_recaptcha(response_token):
    data = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': response_token
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = response.json()
    return result.get('success', False)

def check_remember_token():
    if 'admin' not in session and 'remember_token' in request.cookies:
        token = request.cookies.get('remember_token')
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

        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('INSERT INTO suggestions (grade, content) VALUES (?, ?)', (grade, content))
        suggestion_id = c.lastrowid
        conn.commit()
        conn.close()

        response = make_response(jsonify({'id': suggestion_id}))
        response.set_cookie('last_submit', datetime.now().strftime('%Y-%m-%d'), max_age=86400)
        return response

    return render_template('index.html')

@app.route('/delete_suggestions', methods=['POST'])
def delete_suggestions():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    delete_ids = request.form.getlist('delete_ids')  # 리스트로 받음
    if delete_ids:
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        # 여러 ID를 삭제할 때 IN 절 사용
        query = f"DELETE FROM suggestions WHERE id IN ({','.join(['?']*len(delete_ids))})"
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
        remember = request.form.get('remember')
        recaptcha_response = request.form.get('g-recaptcha-response')

        if os.environ.get('FLASK_ENV') != 'development' and not verify_recaptcha(recaptcha_response):
            return 'CAPTCHA 검증에 실패했습니다.', 401

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT * FROM admin WHERE username=? AND password=?', (username, hashed_password))
        admin = c.fetchone()

        if admin:
            session['admin'] = username
            response = make_response(redirect(url_for('index')))
            if remember == 'on':
                remember_token = secrets.token_hex(32)  # 64자리 랜덤 토큰 생성
                c.execute('UPDATE admin SET remember_token=? WHERE username=?', (remember_token, username))
                conn.commit()
                response.set_cookie(
                    'remember_token', 
                    remember_token, 
                    max_age=30*24*60*60,  # 30일 유지
                    httponly=True,          # JS에서 접근 불가, 보안 강화
                    secure=True if os.environ.get('FLASK_ENV') != 'development' else False  # HTTPS 환경에서만 True
                    )
            conn.close()
            return response
        else:
            conn.close()
            return '로그인 실패', 401

    return render_template('admin_login.html', site_key=RECAPTCHA_SITE_KEY)

@app.before_request
def auto_login():
    if 'admin' not in session:
        token = request.cookies.get('remember_token')
        if token:
            conn = sqlite3.connect('db.sqlite3')
            c = conn.cursor()
            c.execute('SELECT username FROM admin WHERE remember_token=?', (token,))
            admin = c.fetchone()
            conn.close()
            if admin:
                session['admin'] = admin[0]


@app.route('/admin/panel', methods=['GET', 'POST'])
def admin_panel():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()

    if request.method == 'POST':
        ids_to_delete = request.form.getlist('delete_ids')  # 체크된 id 리스트 받기
        if ids_to_delete:
            placeholders = ','.join(['?'] * len(ids_to_delete))
            c.execute(f'DELETE FROM suggestions WHERE id IN ({placeholders})', ids_to_delete)
            conn.commit()

    c.execute('SELECT id, grade, content FROM suggestions ORDER BY timestamp DESC')
    suggestions = c.fetchall()
    conn.close()

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
    app.run(debug=True)