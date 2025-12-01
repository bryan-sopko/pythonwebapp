import sqlite3
from flask import Flask, request, render_template_string
from fastapi import APIRouter
router = APIRouter()

app = Flask(__name__)

# Hardcoded secret key (bad practice)
SECRET_KEY = "super_secret_key_12345"
@router.get('/example')
async def  get_users(user: str):
    await database.fetch_all("SELECT user FROM users WHERE user = '" + user + "'") # Noncompliant
# Hardcoded database credentials (bad practice)
DB_USER = "admin"
DB_PASS = "password"
DB_NAME = "insecure.db"

# NEW: Additional hardcoded credentials
API_KEY = "sk-1234567890abcdef1234567890abcdef"
JWT_SECRET = "my-super-secret-jwt-key-do-not-share"
PAYMENT_KEY = "pk_test_1234567890secretkeydemo"
AUTH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

def get_db():
    # Insecure, no password protection on SQLite
    return sqlite3.connect(DB_NAME)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # SQL Injection vulnerability
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = get_db()
        cursor = conn.cursor()
        # Directly embedding user input in SQL query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        if user:
            return f'Welcome, {username}!'
        else:
            return 'Invalid credentials'
    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/xss')
def xss():
    # XSS vulnerability - directly rendering user input
    user_input = request.args.get('q', '')
    html = f"<h2>Your search: {user_input}</h2>"
    return render_template_string(html)

@app.route('/execute')
def execute_command():
    """NEW: Command injection vulnerability"""
    import os
    cmd = request.args.get('cmd', 'ls')
    # Command injection - directly executing user input
    result = os.system(cmd)
    return f"<h2>Command executed with result: {result}</h2>"

@app.route('/eval')
def eval_code():
    """NEW: Code injection vulnerability"""
    code = request.args.get('code', '1+1')
    # Code injection - using eval with user input
    try:
        result = eval(code)
        return f"<h2>Result: {result}</h2>"
    except Exception as e:
        return f"<h2>Error: {e}</h2>"

@app.route('/pickle_load', methods=['POST'])
def unsafe_pickle():
    """NEW: Unsafe deserialization with pickle"""
    import pickle
    data = request.data
    # Unsafe deserialization - can execute arbitrary code
    obj = pickle.loads(data)
    return f"<h2>Loaded: {str(obj)}</h2>"

@app.route("/")
def home():
    return """
    <h1>Insecure Python App</h1>
    <ul>
        <li><a href='/login'>Login (SQL Injection)</a></li>
        <li><a href='/xss?q=test'>XSS Demo</a></li>
        <li><a href='/execute?cmd=ls'>Command Injection</a></li>
        <li><a href='/eval?code=1+1'>Code Injection</a></li>
    </ul>
    """

@app.route('/path_traversal')
def path_traversal():
    """NEW: Path traversal vulnerability"""
    import os
    filename = request.args.get('file', 'test.txt')
    # Path traversal - no validation on file path
    try:
        with open(f"/var/www/files/{filename}", 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error: {e}"

@app.route('/ssrf')
def ssrf():
    """NEW: Server-Side Request Forgery"""
    import requests
    url = request.args.get('url', 'http://example.com')
    # SSRF - fetching arbitrary URLs
    response = requests.get(url)
    return f"<h2>Response:</h2><pre>{response.text[:1000]}</pre>"

if __name__ == '__main__':
    app.run(debug=True)