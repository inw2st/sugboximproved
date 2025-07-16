from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify
from datetime import datetime, timedelta
import sqlite3
import secrets
import hashlib
import os
import random
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
    
    # Step 1: Check for table and add columns if they don't exist
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='suggestions'")
    if c.fetchone():
        c.execute("PRAGMA table_info(suggestions)")
        columns = [column[1] for column in c.fetchall()]
        
        try:
            if 'public_id' not in columns:
                c.execute('ALTER TABLE suggestions ADD COLUMN public_id TEXT')
                c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_public_id ON suggestions(public_id)')
            if 'user_token' not in columns:
                c.execute('ALTER TABLE suggestions ADD COLUMN user_token TEXT')
                c.execute('CREATE INDEX IF NOT EXISTS idx_user_token ON suggestions(user_token)')
        except sqlite3.OperationalError as e:
            print(f"데이터베이스 스키마 업데이트 중 오류 발생: {e}")

    else:
        # This part is for a completely new database
        c.execute('''CREATE TABLE suggestions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    public_id TEXT UNIQUE,
                    user_token TEXT,
                    grade TEXT NOT NULL,
                    content TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    answer TEXT,
                    status TEXT DEFAULT '대기중',
                    answered_at DATETIME,
                    answered_by TEXT
                )''')

    # Step 2: Data Migration for old records
    c.execute("SELECT id FROM suggestions WHERE public_id IS NULL OR user_token IS NULL")
    records_to_migrate = c.fetchall()

    if records_to_migrate:
        print(f"{len(records_to_migrate)}개의 기존 건의사항을 마이그레이션합니다...")
        for record in records_to_migrate:
            record_id = record[0]
            
            # Generate unique public_id
            while True:
                public_id = str(random.randint(1000, 9999))
                c.execute('SELECT id FROM suggestions WHERE public_id = ?', (public_id,))
                if c.fetchone() is None:
                    break
            
            # Generate a new unique user_token for each old record
            user_token = f"migrated_{secrets.token_hex(12)}"

            c.execute(
                "UPDATE suggestions SET public_id = ?, user_token = ? WHERE id = ?",
                (public_id, user_token, record_id)
            )
        print("데이터 마이그레이션 완료.")

    # Step 3: Ensure admin table exists
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admin'")
    if not c.fetchone():
        c.execute('''CREATE TABLE admin (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    remember_token TEXT
                )''')
        hashed_password = hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute("INSERT OR IGNORE INTO admin (username, password) VALUES (?, ?)", ('admin', hashed_password))

    conn.commit()
    conn.close()
    print("데이터베이스 초기화 및 확인 완료")


def can_submit(request):
    user_ip = request.remote_addr
    if user_ip in ['127.0.0.1', '210.100.145.92']:
        return True
    last_submit = request.cookies.get('last_submit')
    if last_submit:
        try:
            if datetime.strptime(last_submit, '%Y-%m-%d').date() == datetime.now().date():
                return False
        except ValueError:
            pass
    return True


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
        if not data or not data.get('grade') or not data.get('content'):
            return '모든 항목을 입력해주세요.', 400

        if not can_submit(request):
            return '오늘은 이미 건의사항을 제출하셨습니다.', 403

        user_token = request.cookies.get('user_token')
        if not user_token:
            user_token = secrets.token_hex(16)

        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()

        while True:
            public_id = str(random.randint(1000, 9999))
            c.execute('SELECT id FROM suggestions WHERE public_id = ?', (public_id,))
            if c.fetchone() is None:
                break
        
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '알 수 없음')
        
        c.execute('INSERT INTO suggestions (public_id, user_token, grade, content, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)', 
                  (public_id, user_token, data['grade'], data['content'], ip_address, user_agent))
        conn.commit()
        conn.close()

        response = make_response(jsonify({'id': public_id}))
        response.set_cookie('user_token', user_token, max_age=365*24*60*60, httponly=True, secure=request.is_secure)
        response.set_cookie('last_submit', datetime.now().strftime('%Y-%m-%d'), max_age=86400, httponly=True, secure=request.is_secure)
        return response

    html = render_template('index.html')
    response = make_response(html)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route('/my_suggestions')
def my_suggestions():
    user_token = request.cookies.get('user_token')
    suggestions = []
    if user_token:
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute(
            'SELECT public_id, content, status, timestamp FROM suggestions WHERE user_token = ? ORDER BY timestamp DESC',
            (user_token,)
        )
        suggestions = c.fetchall()
        conn.close()
    return render_template('my_suggestions.html', suggestions=suggestions)


@app.route('/delete_suggestions', methods=['POST'])
def delete_suggestions():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))
    delete_ids = request.form.getlist('delete_ids')
    if delete_ids:
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute(f"DELETE FROM suggestions WHERE id IN ({','.join(['?']*len(delete_ids))})", delete_ids)
        conn.commit()
        conn.close()
    return redirect(url_for('admin_panel'))


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'admin' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return render_template('admin_login.html', error="아이디와 비밀번호를 모두 입력해주세요.")

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT * FROM admin WHERE username=? AND password=?', (username, hashed_password))
        admin = c.fetchone()

        if admin:
            session.permanent = True
            session['admin'] = username
            remember_token = secrets.token_hex(32)
            c.execute('UPDATE admin SET remember_token=? WHERE username=?', (remember_token, username))
            conn.commit()
            conn.close()
            response = make_response(redirect(url_for('index')))
            response.set_cookie('remember_token', remember_token, max_age=30*24*60*60, httponly=True, secure=request.is_secure)
            return response
        else:
            conn.close()
            return render_template('admin_login.html', error="로그인에 실패했습니다.")
            
    return render_template('admin_login.html')


@app.route('/admin/panel', methods=['GET'])
def admin_panel():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    c.execute('''
        SELECT id, grade, content, timestamp, status, answer, public_id
        FROM suggestions ORDER BY CASE status WHEN '대기중' THEN 1 ELSE 2 END, timestamp DESC
    ''')
    suggestions = c.fetchall()
    conn.close()
    return render_template('admin_panel.html', suggestions=suggestions)


@app.route('/admin/reply/<int:suggestion_id>', methods=['GET', 'POST'])
def admin_reply(suggestion_id):
    if 'admin' not in session:
        return redirect(url_for('admin_login'))
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    if request.method == 'POST':
        answer = request.form.get('answer')
        if answer:
            c.execute('''
                UPDATE suggestions SET answer = ?, status = '답변 완료', answered_at = ?, answered_by = ?
                WHERE id = ?
            ''', (answer, datetime.now(), session['admin'], suggestion_id))
            conn.commit()
        conn.close()
        return redirect(url_for('admin_panel'))
    c.execute('SELECT id, grade, content, timestamp, answer FROM suggestions WHERE id = ?', (suggestion_id,))
    suggestion = c.fetchone()
    conn.close()
    return render_template('reply.html', suggestion=suggestion) if suggestion else ('건의사항 없음', 404)


@app.route('/suggestion/<suggestion_id>', methods=['GET'])
def view_suggestion(suggestion_id):
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    c.execute('SELECT id, grade, content, timestamp, status, answer, answered_at FROM suggestions WHERE public_id = ?', (suggestion_id,))
    suggestion = c.fetchone()
    conn.close()

    if not suggestion:
        return render_template('check.html', error="해당 ID를 가진 건의사항을 찾을 수 없습니다.")

    back_url = url_for('index')
    if request.referrer:
        if 'my_suggestions' in request.referrer:
            back_url = url_for('my_suggestions')
        elif 'check' in request.referrer:
             back_url = url_for('check_suggestion')

    return render_template('view_suggestion.html', suggestion=suggestion, back_url=back_url)


@app.route('/check', methods=['GET', 'POST'])
def check_suggestion():
    if request.method == 'POST':
        suggestion_id = request.form.get('suggestion_id')
        if suggestion_id:
            conn = sqlite3.connect('db.sqlite3')
            c = conn.cursor()
            c.execute('SELECT id FROM suggestions WHERE public_id = ?', (suggestion_id,))
            exists = c.fetchone()
            conn.close()
            if exists:
                return redirect(url_for('view_suggestion', suggestion_id=suggestion_id))
            else:
                return render_template('check.html', error="해당 ID를 가진 건의사항을 찾을 수 없습니다.")
    return render_template('check.html')


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