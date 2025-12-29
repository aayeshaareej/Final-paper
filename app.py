from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Configure SQLite Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

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
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Create new user instance
        new_user = User(fname=fname, lname=lname, email=email, password=password)
        
        # Add to database
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'User registered successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

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
                'password': user.password
            }
            for user in users
        ]
        return jsonify({'success': True, 'data': users_list})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# UPDATE - Update user
@app.route("/api/users/<int:sno>", methods=['PUT'])
def update_user(sno):
    try:
        user = User.query.get(sno)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        data = request.get_json()
        user.fname = data.get('fname', user.fname)
        user.lname = data.get('lname', user.lname)
        user.email = data.get('email', user.email)
        user.password = data.get('password', user.password)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'User updated successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

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