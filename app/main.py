import sqlite3
from flask import Flask, request, render_template_string
from markupsafe import escape
from fastapi import APIRouter
import yaml
# Before
import os
import sys

def foo():
    return 42
router = APIRouter()

app = Flask(__name__)

# Hardcoded secret key (bad practice)
SECRET_KEY = "super_secret_key_12345"
@router.get('/example')
async def  get_users(user: str):
    await database.fetch_all("SELECT user FROM users WHERE user = '" + user + "'") # Noncompliant

@router.post('/create-order')
async def create_order(user_id: str, product_id: str, quantity: str):
    query = "INSERT INTO orders (user_id, product_id, quantity) VALUES (" + user_id + ", " + product_id + ", " + quantity + ")"
    await database.execute(query) # Noncompliant - SQL injection via string concatenation

@router.delete('/remove-user/{user_id}')
async def remove_user(user_id: str, reason: str = ""):
    delete_query = "DELETE FROM users WHERE id = " + user_id + " AND reason LIKE '%" + reason + "%'"
    await database.execute(delete_query) # Noncompliant - SQL injection in DELETE

@router.put('/update-password')
async def update_password(username: str, old_pass: str, new_pass: str):
    update_sql = f"UPDATE users SET password = '{new_pass}' WHERE username = '{username}' AND password = '{old_pass}'"
    await database.execute(update_sql) # Noncompliant - SQL injection via f-string

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

def upload_to_s3(file_data, filename):
    """Upload file to S3 using hardcoded credentials - CRITICAL VULNERABILITY"""
    import boto3
    
    # VULNERABLE: Using hardcoded AWS credentials
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
    
    try:
        # Upload file to S3 bucket
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=filename,
            Body=file_data
        )
        return f"File {filename} uploaded successfully to {S3_BUCKET_NAME}"
    except Exception as e:
        return f"Upload failed: {str(e)}"

@app.route('/simple-sql', methods=['GET'])
def simple_sql():
    """VERY SIMPLE SQL INJECTION - f-string interpolation like the other vulnerabilities"""
    user_id = request.args.get('user_id', '')
    
    if not user_id:
        return 'Missing user_id parameter'
    
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABLE: f-string interpolation allows SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    result = cursor.fetchone()
    conn.close()
    
    return f"User data: {result}"

@app.route('/login', methods=['GET', 'POST'])
def login():
    # SQL Injection vulnerability
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = get_db()
        cursor = conn.cursor()
        # Fixed: Use parameterized queries to prevent SQL injection
        query = "SELECT * FROM users WHERE username=? AND password=?"
        cursor.execute(query, (username, password))
        
        user = cursor.fetchone()
        conn.close()
        if user:
            return f'Welcome, {escape(username)}!'
        else:
            return 'Invalid credentials'
    return '''
@app.route('/vulnerable-delete', methods=['POST'])
def vulnerable_delete():
    """Vulnerable endpoint: SQL injection in DELETE statement"""
    user_id = request.form.get('user_id', '')
    if not user_id:
        return 'Missing user_id parameter'
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABLE: Direct string interpolation allows SQL injection
    query = f"DELETE FROM users WHERE id = {user_id}"
    cursor.execute(query)
    conn.commit()
    conn.close()
    return f'User {user_id} deleted.'
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
    '''

@app.route('/update-profile', methods=['POST'])
def update_profile():
    """Update user profile - contains SQL injection in UPDATE statement"""
    user_id = request.form.get('user_id', '')
    new_email = request.form.get('email', '')
    
    if not user_id or not new_email:
        return 'Missing user_id or email parameters'
    
    conn = get_db()
    cursor = conn.cursor()
    # Third SQL injection vulnerability - UPDATE statement with string interpolation
    query = f"UPDATE users SET email = '{new_email}' WHERE id = {user_id}"
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return f'Profile updated for user ID {user_id} with email: {new_email}'

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
    <h3>Forms for Testing:</h3>
    <form method="post" action="/update-profile">
        User ID: <input name="user_id" placeholder="1"><br>
        New Email: <input name="email" placeholder="test@example.com"><br>
        <input type="submit" value="Update Profile (SQL Injection #3)">
    </form>
    <form method="post" action="/delete-user">
        User ID to Delete: <input name="user_id" placeholder="1"><br>
        Reason: <input name="reason" placeholder="Account cleanup"><br>
        <input type="submit" value="Delete User (NEW SQL Injection #4)">
    </form>
    <form method="post" action="/upload-avatar">
        User ID: <input name="user_id" placeholder="1"><br>
        Avatar Data: <input name="avatar_data" placeholder="image_data_here"><br>
        <input type="submit" value="Upload Avatar (AWS Credentials Exposure)">
    </form>
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
    app.run(debug=False)