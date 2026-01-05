"""
Vulnerable Flask Web Application for Security Scanner Testing.

This application intentionally contains OWASP Top 10 vulnerabilities
for testing the AI-powered DAST scanner. DO NOT deploy in production!

Vulnerabilities included:
- SQL Injection (multiple endpoints)
- Cross-Site Scripting (XSS) - Reflected, Stored, DOM-based
- Command Injection
- Path Traversal
- Server-Side Request Forgery (SSRF)
- Server-Side Template Injection (SSTI)
- Insecure Deserialization
- XML External Entity (XXE)
"""

import base64
import os
import pickle
import subprocess
import sqlite3

from lxml import etree

import requests
from flask import Flask, request, render_template_string, jsonify, Response

from database import init_db, get_db_connection, reset_db, DATABASE_PATH

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True


def ensure_db_initialized():
    """Ensure database is initialized regardless of how the app is started."""
    if not os.path.exists(DATABASE_PATH):
        init_db()


# Initialize database on import to support all run modes (python app.py, flask run, gunicorn)
ensure_db_initialized()

# In-memory storage for stored XSS comments
stored_comments = []


# =============================================================================
# HOME PAGE
# =============================================================================

HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Web Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        h1 { color: #d32f2f; }
        h2 { color: #333; margin-top: 30px; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .warning { background: #ffebee; border: 2px solid #d32f2f; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .endpoint { background: #e3f2fd; padding: 10px; margin: 5px 0; border-radius: 4px; }
        .endpoint a { color: #1976d2; text-decoration: none; font-weight: bold; }
        .endpoint a:hover { text-decoration: underline; }
        .method { background: #4caf50; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px; margin-right: 10px; }
        .method.post { background: #ff9800; }
        form { background: #fafafa; padding: 15px; margin: 10px 0; border-radius: 4px; }
        input, textarea { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #1976d2; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #1565c0; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔓 Vulnerable Web Application</h1>
    <div class="warning">
        <strong>⚠️ WARNING:</strong> This application contains intentional security vulnerabilities for testing purposes.
        DO NOT deploy in production or expose to untrusted networks!
    </div>

    <h2>SQL Injection Endpoints</h2>
    <div class="endpoint"><span class="method">GET</span><a href="/api/users?id=1">/api/users?id=1</a> - User lookup by ID</div>
    <div class="endpoint"><span class="method">GET</span><a href="/api/products?search=laptop">/api/products?search=laptop</a> - Product search</div>
    <form action="/login" method="POST">
        <span class="method post">POST</span><strong>/login</strong> - Login form<br>
        <input type="text" name="username" placeholder="Username" value="admin">
        <input type="password" name="password" placeholder="Password" value="password">
        <button type="submit">Login</button>
    </form>

    <h2>XSS Endpoints</h2>
    <div class="endpoint"><span class="method">GET</span><a href="/search?q=test">/search?q=test</a> - Reflected XSS in search</div>
    <div class="endpoint"><span class="method">GET</span><a href="/profile?name=John">/profile?name=John</a> - DOM-based XSS</div>
    <form action="/comment" method="POST">
        <span class="method post">POST</span><strong>/comment</strong> - Stored XSS<br>
        <textarea name="comment" placeholder="Enter comment..."></textarea>
        <button type="submit">Submit Comment</button>
    </form>

    <h2>Command Injection</h2>
    <div class="endpoint"><span class="method">GET</span><a href="/ping?host=127.0.0.1">/ping?host=127.0.0.1</a> - Ping command</div>
    <form action="/system" method="POST">
        <span class="method post">POST</span><strong>/system</strong> - System command<br>
        <input type="text" name="cmd" placeholder="Command (e.g., whoami)" value="whoami">
        <button type="submit">Execute</button>
    </form>

    <h2>Path Traversal</h2>
    <div class="endpoint"><span class="method">GET</span><a href="/files?path=document.txt">/files?path=document.txt</a> - File read</div>

    <h2>SSRF</h2>
    <div class="endpoint"><span class="method">GET</span><a href="/fetch?url=http://example.com">/fetch?url=http://example.com</a> - URL fetch</div>

    <h2>SSTI</h2>
    <div class="endpoint"><span class="method">GET</span><a href="/template?name=World">/template?name=World</a> - Template injection</div>

    <h2>Insecure Deserialization</h2>
    <form action="/deserialize" method="POST">
        <span class="method post">POST</span><strong>/deserialize</strong> - Pickle deserialization<br>
        <input type="text" name="data" placeholder="Base64 pickle data">
        <button type="submit">Deserialize</button>
    </form>

    <h2>XXE</h2>
    <form action="/xml" method="POST">
        <span class="method post">POST</span><strong>/xml</strong> - XML parsing<br>
        <textarea name="xml_data" placeholder="Enter XML...">&lt;user&gt;&lt;name&gt;John&lt;/name&gt;&lt;/user&gt;</textarea>
        <button type="submit">Parse XML</button>
    </form>

    <h2>Utility Endpoints</h2>
    <div class="endpoint"><span class="method">GET</span><a href="/health">/health</a> - Health check</div>
    <div class="endpoint"><span class="method">GET</span><a href="/reset">/reset</a> - Reset database</div>
</div>
</body>
</html>
'''

@app.route('/')
def home():
    """Home page with navigation to all vulnerable endpoints."""
    return HOME_TEMPLATE


# =============================================================================
# HEALTH AND UTILITY ENDPOINTS
# =============================================================================

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "message": "Vulnerable app is running"})


@app.route('/reset')
def reset():
    """Reset database to initial state."""
    reset_db()
    stored_comments.clear()
    return jsonify({"status": "ok", "message": "Database reset to initial state"})


# =============================================================================
# SQL INJECTION ENDPOINTS
# =============================================================================

@app.route('/api/users')
def api_users():
    """SQL Injection vulnerable user lookup.

    Vulnerable: Direct string concatenation in SQL query.
    Example payload: 1' OR '1'='1
    """
    user_id = request.args.get('id', '1')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # VULNERABLE: String concatenation allows SQL injection
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)

        users = cursor.fetchall()
        conn.close()

        if users:
            result = [dict(row) for row in users]
            return f'''
            <html>
            <head><title>User Lookup</title></head>
            <body>
            <h1>User Lookup Results</h1>
            <p>Query: {query}</p>
            <table border="1">
                <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
                {"".join(f"<tr><td>{r['id']}</td><td>{r['username']}</td><td>{r['email']}</td><td>{r['role']}</td></tr>" for r in result)}
            </table>
            <p><a href="/">Back to Home</a></p>
            </body>
            </html>
            '''
        else:
            return f"<html><body><h1>No user found</h1><p>Query: {query}</p><a href='/'>Back</a></body></html>"

    except sqlite3.Error as e:
        # VULNERABLE: Exposing SQL errors helps attackers
        return f'''
        <html>
        <head><title>SQL Error</title></head>
        <body>
        <h1>Database Error</h1>
        <p style="color: red; font-family: monospace;">
            Error: {str(e)}<br>
            Query: {query}
        </p>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        ''', 500


@app.route('/api/products')
def api_products():
    """SQL Injection vulnerable product search.

    Vulnerable: LIKE clause with string concatenation.
    Example payload: ' UNION SELECT 1,username,password,email FROM users--
    """
    search = request.args.get('search', '')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # VULNERABLE: String concatenation allows SQL injection
        query = f"SELECT * FROM products WHERE name LIKE '%{search}%'"
        cursor.execute(query)

        products = cursor.fetchall()
        conn.close()

        result = [dict(row) for row in products]
        return jsonify({
            "query": query,
            "count": len(result),
            "products": result
        })

    except sqlite3.Error as e:
        # VULNERABLE: Exposing SQL errors
        return jsonify({
            "error": str(e),
            "query": query
        }), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    """SQL Injection vulnerable login.

    Vulnerable: Direct string formatting in WHERE clause.
    Example payload: admin'-- (bypasses password check)
    """
    if request.method == 'GET':
        return '''
        <html>
        <head><title>Login</title></head>
        <body>
        <h1>Login</h1>
        <form method="POST">
            <input type="text" name="username" placeholder="Username"><br><br>
            <input type="password" name="password" placeholder="Password"><br><br>
            <button type="submit">Login</button>
        </form>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        '''

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # VULNERABLE: SQL injection in login
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor.execute(query)

        user = cursor.fetchone()
        conn.close()

        if user:
            return f'''
            <html>
            <head><title>Login Successful</title></head>
            <body>
            <h1 style="color: green;">Login Successful!</h1>
            <p>Welcome, {user['username']}!</p>
            <p>Role: {user['role']}</p>
            <p>Email: {user['email']}</p>
            <p>Query executed: <code>{query}</code></p>
            <p><a href="/">Back to Home</a></p>
            </body>
            </html>
            '''
        else:
            return f'''
            <html>
            <head><title>Login Failed</title></head>
            <body>
            <h1 style="color: red;">Login Failed</h1>
            <p>Invalid username or password</p>
            <p>Query executed: <code>{query}</code></p>
            <p><a href="/login">Try Again</a></p>
            </body>
            </html>
            ''', 401

    except sqlite3.Error as e:
        return f'''
        <html>
        <head><title>Error</title></head>
        <body>
        <h1>Database Error</h1>
        <p style="color: red;">{str(e)}</p>
        <p>Query: {query}</p>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        ''', 500



# =============================================================================
# XSS ENDPOINTS
# =============================================================================

@app.route('/search')
def search():
    """Reflected XSS vulnerable search.

    Vulnerable: User input reflected directly in HTML without encoding.
    Example payload: <script>alert('XSS')</script>
    """
    query = request.args.get('q', '')

    # VULNERABLE: Direct reflection of user input
    return f'''
    <html>
    <head><title>Search Results</title></head>
    <body>
    <h1>Search Results</h1>
    <h2>Results for: {query}</h2>
    <p>Your search query was: {query}</p>
    <form action="/search" method="GET">
        <input type="text" name="q" value="{query}" placeholder="Search...">
        <button type="submit">Search</button>
    </form>
    <p>No results found for your query.</p>
    <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    '''


@app.route('/comment', methods=['GET', 'POST'])
def comment():
    """Stored XSS vulnerable comment system.

    Vulnerable: Comments stored and displayed without sanitization.
    Example payload: <img src=x onerror=alert('XSS')>
    """
    if request.method == 'POST':
        new_comment = request.form.get('comment', '')
        if new_comment:
            stored_comments.append(new_comment)

    # VULNERABLE: Stored comments displayed without encoding
    comments_html = "\n".join([
        f"<div class='comment'><p>{c}</p></div>"
        for c in stored_comments
    ])

    return f'''
    <html>
    <head>
        <title>Comments</title>
        <style>
            .comment {{ background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 4px; }}
        </style>
    </head>
    <body>
    <h1>Comments Section</h1>
    <form method="POST">
        <textarea name="comment" placeholder="Enter your comment..."></textarea><br>
        <button type="submit">Submit Comment</button>
    </form>
    <h2>All Comments ({len(stored_comments)}):</h2>
    {comments_html if comments_html else "<p>No comments yet.</p>"}
    <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    '''


@app.route('/profile')
def profile():
    """DOM-based XSS vulnerable profile page.

    Vulnerable: User input injected into JavaScript context.
    Example payload: '; alert('XSS'); //
    """
    name = request.args.get('name', 'Guest')

    # VULNERABLE: User input in JavaScript context
    return f'''
    <html>
    <head><title>Profile</title></head>
    <body>
    <h1>User Profile</h1>
    <div id="greeting"></div>
    <script>
        var username = '{name}';
        document.getElementById('greeting').innerHTML = 'Welcome, ' + username + '!';
    </script>
    <p>Name parameter: {name}</p>
    <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    '''


# =============================================================================
# COMMAND INJECTION ENDPOINTS
# =============================================================================

@app.route('/ping')
def ping():
    """Command injection vulnerable ping endpoint.

    Vulnerable: User input passed directly to shell command.
    Example payload: 127.0.0.1; cat /etc/passwd
    """
    host = request.args.get('host', '127.0.0.1')

    try:
        # VULNERABLE: Shell injection via subprocess with shell=True
        result = subprocess.run(
            f"ping -c 1 {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Command timed out"
    except Exception as e:
        output = f"Error: {str(e)}"

    return f'''
    <html>
    <head><title>Ping Result</title></head>
    <body>
    <h1>Ping Result</h1>
    <p>Command: ping -c 1 {host}</p>
    <pre style="background: #f0f0f0; padding: 15px; overflow-x: auto;">{output}</pre>
    <form action="/ping" method="GET">
        <input type="text" name="host" value="{host}" placeholder="Host to ping">
        <button type="submit">Ping</button>
    </form>
    <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    '''


@app.route('/system', methods=['GET', 'POST'])
def system():
    """Command injection vulnerable system command endpoint.

    Vulnerable: Direct command execution with os.popen.
    Example payload: id; cat /etc/passwd
    """
    if request.method == 'GET':
        return '''
        <html>
        <head><title>System Command</title></head>
        <body>
        <h1>System Command Executor</h1>
        <form method="POST">
            <input type="text" name="cmd" placeholder="Enter command">
            <button type="submit">Execute</button>
        </form>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        '''

    cmd = request.form.get('cmd', 'whoami')

    try:
        # VULNERABLE: Direct command execution
        output = os.popen(cmd).read()
    except Exception as e:
        output = f"Error: {str(e)}"

    return f'''
    <html>
    <head><title>Command Output</title></head>
    <body>
    <h1>Command Output</h1>
    <p>Command: {cmd}</p>
    <pre style="background: #f0f0f0; padding: 15px; overflow-x: auto;">{output}</pre>
    <form method="POST">
        <input type="text" name="cmd" value="{cmd}" placeholder="Enter command">
        <button type="submit">Execute</button>
    </form>
    <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    '''


# =============================================================================
# PATH TRAVERSAL ENDPOINT
# =============================================================================

@app.route('/files')
def files():
    """Path traversal vulnerable file read endpoint.

    Vulnerable: No sanitization of file path allows directory traversal.
    Example payload: ../../etc/passwd
    """
    file_path = request.args.get('path', 'readme.txt')

    # Get the base directory for files
    base_dir = os.path.join(os.path.dirname(__file__), 'files')

    # VULNERABLE: No path sanitization - allows directory traversal
    full_path = os.path.join(base_dir, file_path)

    try:
        with open(full_path, 'r') as f:
            content = f.read()

        return f'''
        <html>
        <head><title>File Contents</title></head>
        <body>
        <h1>File Contents</h1>
        <p>File: {file_path}</p>
        <p>Full path: {full_path}</p>
        <pre style="background: #f0f0f0; padding: 15px; overflow-x: auto;">{content}</pre>
        <form action="/files" method="GET">
            <input type="text" name="path" value="{file_path}" placeholder="File path">
            <button type="submit">Read File</button>
        </form>
        <h3>Available files:</h3>
        <ul>
            <li><a href="/files?path=document.txt">document.txt</a></li>
            <li><a href="/files?path=config.ini">config.ini</a></li>
            <li><a href="/files?path=readme.txt">readme.txt</a></li>
        </ul>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        '''
    except FileNotFoundError:
        return f'''
        <html>
        <head><title>File Not Found</title></head>
        <body>
        <h1>File Not Found</h1>
        <p style="color: red;">Error: File not found: {full_path}</p>
        <p>Requested path: {file_path}</p>
        <p><a href="/files">Try another file</a></p>
        </body>
        </html>
        ''', 404
    except PermissionError:
        return f'''
        <html>
        <head><title>Permission Denied</title></head>
        <body>
        <h1>Permission Denied</h1>
        <p style="color: red;">Error: Permission denied reading: {full_path}</p>
        <p><a href="/files">Try another file</a></p>
        </body>
        </html>
        ''', 403
    except Exception as e:
        return f'''
        <html>
        <head><title>Error</title></head>
        <body>
        <h1>Error Reading File</h1>
        <p style="color: red;">Error: {str(e)}</p>
        <p>Path: {full_path}</p>
        <p><a href="/files">Try another file</a></p>
        </body>
        </html>
        ''', 500


# =============================================================================
# SSRF ENDPOINT
# =============================================================================

@app.route('/fetch')
def fetch():
    """SSRF vulnerable URL fetch endpoint.

    Vulnerable: No URL validation allows internal network access.
    Example payload: http://localhost:8080/api/users?id=1
    """
    url = request.args.get('url', '')

    if not url:
        return '''
        <html>
        <head><title>URL Fetch</title></head>
        <body>
        <h1>URL Fetcher</h1>
        <form action="/fetch" method="GET">
            <input type="text" name="url" placeholder="Enter URL to fetch" style="width: 400px;">
            <button type="submit">Fetch</button>
        </form>
        <h3>Example URLs:</h3>
        <ul>
            <li><a href="/fetch?url=http://example.com">http://example.com</a></li>
            <li><a href="/fetch?url=http://localhost:8080/api/users?id=1">http://localhost:8080/api/users?id=1</a> (SSRF to internal API)</li>
            <li><a href="/fetch?url=http://127.0.0.1:8080/health">http://127.0.0.1:8080/health</a> (Internal health check)</li>
        </ul>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        '''

    try:
        # VULNERABLE: No URL validation - allows SSRF attacks
        response = requests.get(url, timeout=10)
        content = response.text[:5000]  # Limit response size
        status = response.status_code
        headers = dict(response.headers)

        return f'''
        <html>
        <head><title>Fetch Result</title></head>
        <body>
        <h1>Fetch Result</h1>
        <p><strong>URL:</strong> {url}</p>
        <p><strong>Status:</strong> {status}</p>
        <p><strong>Headers:</strong></p>
        <pre style="background: #e0e0e0; padding: 10px;">{headers}</pre>
        <p><strong>Content:</strong></p>
        <pre style="background: #f0f0f0; padding: 15px; overflow-x: auto; max-height: 400px;">{content}</pre>
        <form action="/fetch" method="GET">
            <input type="text" name="url" value="{url}" style="width: 400px;">
            <button type="submit">Fetch Again</button>
        </form>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        '''
    except requests.exceptions.RequestException as e:
        return f'''
        <html>
        <head><title>Fetch Error</title></head>
        <body>
        <h1>Fetch Error</h1>
        <p style="color: red;">Error fetching URL: {str(e)}</p>
        <p>Attempted URL: {url}</p>
        <p><a href="/fetch">Try another URL</a></p>
        </body>
        </html>
        ''', 500


# =============================================================================
# SSTI ENDPOINT
# =============================================================================

@app.route('/template')
def template():
    """SSTI vulnerable template rendering endpoint.

    Vulnerable: User input passed directly to render_template_string.
    Example payload: {{7*7}} or {{config}}
    """
    name = request.args.get('name', 'World')

    # VULNERABLE: Direct user input in template string
    template_str = f"Hello {name}!"

    try:
        rendered = render_template_string(template_str)

        return f'''
        <html>
        <head><title>Template Demo</title></head>
        <body>
        <h1>Template Demo</h1>
        <p><strong>Template:</strong> <code>Hello {{{{name}}}}!</code></p>
        <p><strong>Input:</strong> {name}</p>
        <p><strong>Result:</strong> {rendered}</p>
        <form action="/template" method="GET">
            <input type="text" name="name" value="{name}" placeholder="Enter name">
            <button type="submit">Render</button>
        </form>
        <h3>Try these payloads:</h3>
        <ul>
            <li><a href="/template?name={{{{7*7}}}}">{{{{7*7}}}}</a> - Math expression</li>
            <li><a href="/template?name={{{{config}}}}">{{{{config}}}}</a> - Config access</li>
        </ul>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        '''
    except Exception as e:
        return f'''
        <html>
        <head><title>Template Error</title></head>
        <body>
        <h1>Template Error</h1>
        <p style="color: red;">Error rendering template: {str(e)}</p>
        <p>Input: {name}</p>
        <p><a href="/template">Try again</a></p>
        </body>
        </html>
        ''', 500


# =============================================================================
# INSECURE DESERIALIZATION ENDPOINT
# =============================================================================

@app.route('/deserialize', methods=['GET', 'POST'])
def deserialize():
    """Insecure deserialization vulnerable endpoint.

    Vulnerable: Unpickles user-provided data without validation.
    Example: Create a malicious pickle payload and base64 encode it.
    """
    if request.method == 'GET':
        # Generate a sample safe payload for demonstration
        sample_data = {"user": "demo", "role": "guest"}
        sample_encoded = base64.b64encode(pickle.dumps(sample_data)).decode()

        return f'''
        <html>
        <head><title>Deserialization Demo</title></head>
        <body>
        <h1>Deserialization Demo</h1>
        <p>This endpoint accepts base64-encoded pickle data and deserializes it.</p>
        <form method="POST">
            <textarea name="data" rows="3" cols="60" placeholder="Base64-encoded pickle data">{sample_encoded}</textarea><br><br>
            <button type="submit">Deserialize</button>
        </form>
        <h3>Sample data:</h3>
        <p>Original: <code>{sample_data}</code></p>
        <p>Encoded: <code>{sample_encoded}</code></p>
        <p style="color: orange;"><strong>Warning:</strong> pickle.loads() is vulnerable to arbitrary code execution!</p>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        '''

    data = request.form.get('data', '')

    try:
        # VULNERABLE: Deserializing untrusted pickle data
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)

        return f'''
        <html>
        <head><title>Deserialization Result</title></head>
        <body>
        <h1>Deserialization Result</h1>
        <p><strong>Input (Base64):</strong> <code>{data[:100]}...</code></p>
        <p><strong>Deserialized Object:</strong></p>
        <pre style="background: #f0f0f0; padding: 15px;">{obj}</pre>
        <p><strong>Type:</strong> {type(obj).__name__}</p>
        <form method="POST">
            <textarea name="data" rows="3" cols="60">{data}</textarea><br><br>
            <button type="submit">Deserialize Again</button>
        </form>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        '''
    except Exception as e:
        return f'''
        <html>
        <head><title>Deserialization Error</title></head>
        <body>
        <h1>Deserialization Error</h1>
        <p style="color: red;">Error: {str(e)}</p>
        <p>Input: {data[:100]}...</p>
        <p><a href="/deserialize">Try again</a></p>
        </body>
        </html>
        ''', 400


# =============================================================================
# XXE ENDPOINT
# =============================================================================

@app.route('/xml', methods=['GET', 'POST'])
def xml_parse():
    """XXE vulnerable XML parsing endpoint.

    Vulnerable: XML parser with external entity expansion enabled using lxml.
    Example payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user>&xxe;</user>
    """
    if request.method == 'GET':
        sample_xml = '<user><name>John</name><email>john@example.com</email></user>'

        return f'''
        <html>
        <head><title>XML Parser</title></head>
        <body>
        <h1>XML Parser</h1>
        <form method="POST">
            <textarea name="xml_data" rows="6" cols="60" placeholder="Enter XML data">{sample_xml}</textarea><br><br>
            <button type="submit">Parse XML</button>
        </form>
        <h3>Try this XXE payload:</h3>
        <pre style="background: #fff3e0; padding: 10px;">
&lt;!DOCTYPE foo [
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;user&gt;&amp;xxe;&lt;/user&gt;
        </pre>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        '''

    xml_data = request.form.get('xml_data', '')

    try:
        # VULNERABLE: lxml parser configured to load DTD and resolve external entities
        # This allows XXE attacks to read local files or make network requests
        parser = etree.XMLParser(
            load_dtd=True,
            resolve_entities=True,
            no_network=False
        )
        root = etree.fromstring(xml_data.encode('utf-8'), parser=parser)

        # Convert parsed XML to string representation (entities are now expanded)
        parsed_content = etree.tostring(root, encoding='unicode')

        # Extract text content (includes expanded entity values)
        text_content = ''.join(root.itertext())

        return f'''
        <html>
        <head><title>XML Parse Result</title></head>
        <body>
        <h1>XML Parse Result</h1>
        <p><strong>Input XML:</strong></p>
        <pre style="background: #f0f0f0; padding: 10px;">{xml_data}</pre>
        <p><strong>Parsed Structure:</strong></p>
        <pre style="background: #e8f5e9; padding: 10px;">{parsed_content}</pre>
        <p><strong>Text Content:</strong></p>
        <pre style="background: #e3f2fd; padding: 10px;">{text_content}</pre>
        <p><strong>Root Tag:</strong> {root.tag}</p>
        <form method="POST">
            <textarea name="xml_data" rows="6" cols="60">{xml_data}</textarea><br><br>
            <button type="submit">Parse Again</button>
        </form>
        <p><a href="/">Back to Home</a></p>
        </body>
        </html>
        '''
    except etree.XMLSyntaxError as e:
        return f'''
        <html>
        <head><title>XML Parse Error</title></head>
        <body>
        <h1>XML Parse Error</h1>
        <p style="color: red;">Parse Error: {str(e)}</p>
        <p><strong>Input:</strong></p>
        <pre style="background: #ffebee; padding: 10px;">{xml_data}</pre>
        <p><a href="/xml">Try again</a></p>
        </body>
        </html>
        ''', 400
    except Exception as e:
        return f'''
        <html>
        <head><title>Error</title></head>
        <body>
        <h1>Error Processing XML</h1>
        <p style="color: red;">Error: {str(e)}</p>
        <p><a href="/xml">Try again</a></p>
        </body>
        </html>
        ''', 500


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    # Ensure database is initialized (redundant but explicit for direct execution)
    ensure_db_initialized()

    print("=" * 60)
    print("VULNERABLE WEB APPLICATION")
    print("=" * 60)
    print("WARNING: This application contains intentional vulnerabilities!")
    print("DO NOT deploy in production or expose to untrusted networks!")
    print("=" * 60)
    print()
    print("Starting server on http://0.0.0.0:8080")
    print()

    # Run Flask app
    app.run(host='0.0.0.0', port=8080, debug=False)