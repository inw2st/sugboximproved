import sqlite3
import hashlib

# 새 로그인 정보
username = 'admin0306'
password = 'jihoo090306'

# 비밀번호를 SHA-256으로 해싱
hashed_password = hashlib.sha256(password.encode()).hexdigest()

# DB 연결
conn = sqlite3.connect('db.sqlite3')
c = conn.cursor()

# 기존 admin 계정 삭제 (선택 사항)
c.execute('DELETE FROM admin')

# 새로운 admin 계정 삽입
c.execute('INSERT INTO admin (username, password) VALUES (?, ?)', (username, hashed_password))

conn.commit()
conn.close()

print("새 관리자 계정이 생성되었습니다: admin0306 / jihoo090306")
