import sqlite3
from flask import Flask, request, render_template_string
from markupsafe import escape
from fastapi import APIRouter
import yaml
# Before
import os
import sys
import subprocess

def foo():
    return 42

# NEW: Weak cryptographic function
def weak_hash_password(password):
    import hashlib
    # Using MD5 for password hashing - INSECURE!
    return hashlib.md5(password.encode()).hexdigest()

router = APIRouter()

app = Flask(__name__)

# Hardcoded secret key (bad practice)
SECRET_KEY = "super_secret_key_12345"

# NEW: Another hardcoded secret
DATABASE_PASSWORD = "admin123!@#"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

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

# Hardcoded AWS credentials (CRITICAL security issue)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "kHeUAwnSUizTWpSbyGAz4f+As5LshPIjvtpswqGb"
AWS_REGION = "us-east-1"
S3_BUCKET_NAME = "my-app-uploads"
router = APIRouter()

@router.get('/example')
async def  get_users(user: str):
    await database.fetch_all("SELECT user FROM users WHERE user = '" + user + "'")
def load_config(raw: str) -> dict:
    # Unsafe: can construct arbitrary Python objects
    return yaml.load(raw)
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

@app.route('/run-command', methods=['POST'])
def run_command():
    """NEW: Direct command execution - OS command injection"""
    cmd = request.form.get('command', '')
    # CRITICAL: Direct execution of user input
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return f"<pre>Output:\n{result.stdout}\nErrors:\n{result.stderr}</pre>"

@app.route('/weak-crypto', methods=['POST'])
def weak_crypto():
    """NEW: Using weak cryptography for passwords"""
    password = request.form.get('password', '')
    hashed = weak_hash_password(password)
    return f"Your 'secure' hash: {hashed}"

@app.route('/xss')
def xss():
    # XSS vulnerability - directly rendering user input
    user_input = request.args.get('q', '')
    html = f"<h2>Your search: {user_input}</h2>"
    return render_template_string(html)

@app.route('/search-users')
def search_users():
    """Search users endpoint with SQL injection vulnerability"""
    search_query = request.args.get('q', '')
    if not search_query:
        return 'Please provide a search query using ?q=searchterm'
    
    conn = get_db()
    cursor = conn.cursor()
    # Another SQL injection vulnerability - using LIKE with direct string interpolation
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search_query}%' OR email LIKE '%{search_query}%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    if results:
        user_list = ""
        for user in results:
            user_list += f"<li>ID: {user[0]}, Username: {user[1]}, Email: {user[2]}</li>"
        return f"<h2>Search Results:</h2><ul>{user_list}</ul>"
    else:
        return f"<h2>No users found for: {search_query}</h2>"

@app.route('/delete-user', methods=['POST'])
def delete_user():
    """NEW VULNERABLE ENDPOINT - SQL injection in DELETE statement"""
    user_id = request.form.get('user_id', '')
    reason = request.form.get('reason', 'No reason provided')
    
    if not user_id:
        return 'Missing user_id parameter'
    
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation in DELETE query
    query = f"DELETE FROM users WHERE id = {user_id} AND status = 'active'"
    cursor.execute(query)
    
    # Also vulnerable: Log the deletion with string interpolation
    log_query = f"INSERT INTO audit_log (action, details) VALUES ('DELETE', 'User {user_id} deleted: {reason}')"
    cursor.execute(log_query)
    
    conn.commit()
    conn.close()
    
    return f'User {user_id} has been deleted. Reason: {reason}'

@app.route('/upload-avatar', methods=['POST'])
def upload_avatar():
    """Upload user avatar - exposes AWS credentials vulnerability"""
    user_id = request.form.get('user_id', '')
    avatar_data = request.form.get('avatar_data', 'default_avatar_content')
    
    if not user_id:
        return 'Missing user_id parameter'
    
    # VULNERABLE: Function uses hardcoded AWS credentials
    filename = f"avatars/user_{user_id}_avatar.jpg"
    result = upload_to_s3(avatar_data.encode(), filename)
    
    return f'Avatar upload result: {result}'

@app.route('/get-user-orders', methods=['GET'])
def get_user_orders():
    """Get user orders - VULNERABLE to SQL injection via direct concatenation"""
    user_id = request.args.get('user_id', '')
    status_filter = request.args.get('status', 'active')
    
    if not user_id:
        return 'Missing user_id parameter'
    
    conn = get_db()
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation allows SQL injection
    query = "SELECT * FROM orders WHERE user_id = " + user_id + " AND status = '" + status_filter + "'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    
    if results:
        order_list = "<h2>Orders:</h2><ul>"
        for order in results:
            order_list += f"<li>Order ID: {order[0]}, Amount: ${order[1]}, Status: {order[2]}</li>"
        order_list += "</ul>"
        return order_list
    else:
        return f"<h2>No orders found for user {user_id} with status '{status_filter}'</h2>"

@app.route("/")
def home():
    return """
    <h1>Insecure Python App</h1>
    <ul>
        <li><a href='/login'>Login (SQL Injection)</a></li>
        <li><a href='/xss?q=test'>XSS Demo</a></li>
        <li><a href='/search-users?q=admin'>Search Users (SQL Injection #2)</a></li>
        <li><a href='/get-user-orders?user_id=1&status=active'>Get Orders (SQL Injection #5)</a></li>
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

if __name__ == '__main__':
    app.run(debug=False)