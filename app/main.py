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

@app.route("/")
def home():
    return """
    <h1>Insecure Python App</h1>
    <ul>
        <li><a href='/login'>Login (SQL Injection)</a></li>
        <li><a href='/xss?q=test'>XSS Demo</a></li>
    </ul>
    """

if __name__ == '__main__':
    app.run(debug=True)