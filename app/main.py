import sqlite3
from flask import Flask, request, render_template_string
from markupsafe import escape
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

@app.route("/")
def home():
    return """
    <h1>Insecure Python App</h1>
    <ul>
        <li><a href='/login'>Login (SQL Injection)</a></li>
        <li><a href='/xss?q=test'>XSS Demo</a></li>
        <li><a href='/search-users?q=admin'>Search Users (SQL Injection #2)</a></li>
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
    """

if __name__ == '__main__':
    app.run(debug=False)