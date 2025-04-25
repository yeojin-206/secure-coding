# secure-coding
## 개발 환경 설정

이 프로젝트는 Python 기반 Flask 프레임워크로 구성되어 있으며, 다음과 같은 환경 설정이 필요합니다.

### 1. 가상환경 생성 (선택 사항)
```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 2. 패키지 설치
```bash
pip install flask flask-wtf flask-socketio eventlet
pip install werkzeug
pip install itsdangerous
pip install jinja2
pip install click
```

### 3. Flask 실행
```bash
python app.py
```

### 4. 서버 접속
브라우저에서 [http://127.0.0.1:5000](http://localhost:5000) 으로 접속합니다.
---