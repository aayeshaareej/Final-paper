from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
import re
import bleach

app = Flask(__name__)

# Configure SQLite Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# ============ VALIDATION FUNCTIONS ============

def validate_name(name):
    """Validate name field - only alphanumeric and spaces allowed"""
    if not name or len(name.strip()) == 0:
        return False, "Name cannot be empty"
    if len(name) > 100:
        return False, "Name must be less than 100 characters"
    # Only allow letters, spaces, hyphens, and apostrophes
    if not re.match(r"^[a-zA-Z\s\-']{1,100}$", name):
        return False, "Name contains invalid characters. Only letters, spaces, hyphens, and apostrophes allowed"
    return True, None

def validate_email(email):
    """Validate email format"""
    if not email or len(email.strip()) == 0:
        return False, "Email cannot be empty"
    if len(email) > 100:
        return False, "Email must be less than 100 characters"
    # RFC 5322 simplified email regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    return True, None

def validate_password(password):
    """Validate password strength"""
    if not password:
        return False, "Password cannot be empty"
    if len(password) < 6:
        return False, "Password must be at least 6 characters"
    if len(password) > 100:
        return False, "Password must be less than 100 characters"
    return True, None

def sanitize_input(user_input):
    """Sanitize user input to prevent XSS attacks"""
    if not user_input:
        return ""
    # Remove any HTML/script tags
    sanitized = bleach.clean(user_input, tags=[], strip=True)
    # Strip leading/trailing whitespace
    sanitized = sanitized.strip()
    return sanitized

def check_sql_injection_patterns(user_input):
    """Check for common SQL injection patterns"""
    if not user_input:
        return False
    
    # SQL injection patterns to detect
    sql_patterns = [
        r"('\s*(OR|AND)\s*')",
        r"(DROP\s+(TABLE|DATABASE|USER))",
        r"(UNION\s+SELECT)",
        r"(INSERT\s+INTO)",
        r"(DELETE\s+FROM)",
        r"(UPDATE\s+\w+\s+SET)",
        r"(SELECT\s+\*\s+FROM)",
        r"(--|#|/\*|\*/)",
    ]
    
    text_upper = user_input.upper()
    for pattern in sql_patterns:
        if re.search(pattern, text_upper):
            return True
    return False

# Define User Model
class User(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)

@app.route("/")
def hello_world():
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    
    return render_template('index.html')

# CREATE - Register User
@app.route("/register", methods=['POST'])
def register():
    try:
        # Get form data
        fname = request.form.get('fname', '').strip()
        lname = request.form.get('lname', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # ============ VALIDATION CHECKS ============
        
        # Check for SQL injection patterns
        for field, value in [('fname', fname), ('lname', lname), ('email', email), ('password', password)]:
            if check_sql_injection_patterns(value):
                return jsonify({'success': False, 'message': f'Invalid characters detected in {field}. Suspicious input rejected.'})
        
        # Validate first name
        is_valid, error_msg = validate_name(fname)
        if not is_valid:
            return jsonify({'success': False, 'message': f'First Name: {error_msg}'})
        
        # Validate last name
        is_valid, error_msg = validate_name(lname)
        if not is_valid:
            return jsonify({'success': False, 'message': f'Last Name: {error_msg}'})
        
        # Validate email
        is_valid, error_msg = validate_email(email)
        if not is_valid:
            return jsonify({'success': False, 'message': f'Email: {error_msg}'})
        
        # Validate password
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return jsonify({'success': False, 'message': f'Password: {error_msg}'})
        
        # Sanitize inputs
        fname = sanitize_input(fname)
        lname = sanitize_input(lname)
        email = sanitize_input(email)
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'success': False, 'message': 'Email already registered'})
        
        # Hash password before storing
        hashed_password = generate_password_hash(password)
        
        # Create new user instance
        new_user = User(fname=fname, lname=lname, email=email, password=hashed_password)
        
        # Add to database
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'User registered successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Registration error: Invalid input provided'})

# READ - Get all users
@app.route("/api/users", methods=['GET'])
def get_users():
    try:
        users = User.query.all()
        users_list = [
            {
                'sno': user.sno,
                'fname': user.fname,
                'lname': user.lname,
                'email': user.email,
                'password': '••••••'  # Don't return actual password
            }
            for user in users
        ]
        return jsonify({'success': True, 'data': users_list})
    except Exception as e:
        print(f"Error in get_users: {str(e)}")
        return jsonify({'success': False, 'message': str(e), 'data': []})

# UPDATE - Update user
@app.route("/api/users/<int:sno>", methods=['PUT'])
def update_user(sno):
    try:
        user = User.query.get(sno)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        data = request.get_json()
        
        # Validate and sanitize fname if provided
        if 'fname' in data and data['fname']:
            fname = data['fname'].strip()
            # Check for SQL injection
            if check_sql_injection_patterns(fname):
                return jsonify({'success': False, 'message': 'Invalid characters in first name'})
            # Validate
            is_valid, error_msg = validate_name(fname)
            if not is_valid:
                return jsonify({'success': False, 'message': f'First Name: {error_msg}'})
            user.fname = sanitize_input(fname)
        
        # Validate and sanitize lname if provided
        if 'lname' in data and data['lname']:
            lname = data['lname'].strip()
            # Check for SQL injection
            if check_sql_injection_patterns(lname):
                return jsonify({'success': False, 'message': 'Invalid characters in last name'})
            # Validate
            is_valid, error_msg = validate_name(lname)
            if not is_valid:
                return jsonify({'success': False, 'message': f'Last Name: {error_msg}'})
            user.lname = sanitize_input(lname)
        
        # Validate and sanitize email if provided
        if 'email' in data and data['email']:
            email = data['email'].strip()
            # Check for SQL injection
            if check_sql_injection_patterns(email):
                return jsonify({'success': False, 'message': 'Invalid characters in email'})
            # Validate email
            is_valid, error_msg = validate_email(email)
            if not is_valid:
                return jsonify({'success': False, 'message': f'Email: {error_msg}'})
            # Check if email already exists (excluding current user)
            existing_user = User.query.filter(User.email == email, User.sno != sno).first()
            if existing_user:
                return jsonify({'success': False, 'message': 'Email already in use'})
            user.email = sanitize_input(email)
        
        # Validate and hash password if provided
        if 'password' in data and data['password']:
            password = data['password']
            # Validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                return jsonify({'success': False, 'message': f'Password: {error_msg}'})
            # Hash the new password
            user.password = generate_password_hash(password)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'User updated successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Update error: Invalid input provided'})

# DELETE - Delete user
@app.route("/api/users/<int:sno>", methods=['DELETE'])
def delete_user(sno):
    try:
        user = User.query.get(sno)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User deleted successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

if __name__ == "__main__":
    app.run(debug=True)