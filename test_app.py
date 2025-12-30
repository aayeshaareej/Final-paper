import pytest
import json
from app import app, db, User
from werkzeug.security import check_password_hash


@pytest.fixture
def client():
    """Create a test client with a temporary database"""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


@pytest.fixture
def sample_user(client):
    """Create a sample user for testing"""
    with app.app_context():
        user = User(
            fname='John',
            lname='Doe',
            email='john@example.com',
            password='hashedpassword123'
        )
        db.session.add(user)
        db.session.commit()
        return user


# ============ VALIDATION FUNCTION TESTS ============

class TestValidateName:
    """Test cases for validate_name function"""
    
    def test_valid_name(self):
        """Test validate_name with valid input"""
        from app import validate_name
        is_valid, error_msg = validate_name('John')
        assert is_valid is True
        assert error_msg is None

    def test_empty_name(self):
        """Test validate_name with empty input"""
        from app import validate_name
        is_valid, error_msg = validate_name('')
        assert is_valid is False
        assert 'empty' in error_msg.lower()

    def test_too_long_name(self):
        """Test validate_name with too long input"""
        from app import validate_name
        is_valid, error_msg = validate_name('a' * 101)
        assert is_valid is False
        assert '100' in error_msg

    def test_invalid_characters_in_name(self):
        """Test validate_name with invalid characters"""
        from app import validate_name
        is_valid, error_msg = validate_name('John@123')
        assert is_valid is False
        assert 'invalid' in error_msg.lower()

    def test_name_with_hyphen(self):
        """Test validate_name with hyphens (allowed)"""
        from app import validate_name
        is_valid, error_msg = validate_name('Mary-Jane')
        assert is_valid is True

    def test_name_with_apostrophe(self):
        """Test validate_name with apostrophe (allowed)"""
        from app import validate_name
        is_valid, error_msg = validate_name("O'Brien")
        assert is_valid is True


class TestValidateEmail:
    """Test cases for validate_email function"""
    
    def test_valid_email(self):
        """Test validate_email with valid email"""
        from app import validate_email
        is_valid, error_msg = validate_email('test@example.com')
        assert is_valid is True
        assert error_msg is None

    def test_empty_email(self):
        """Test validate_email with empty input"""
        from app import validate_email
        is_valid, error_msg = validate_email('')
        assert is_valid is False
        assert 'empty' in error_msg.lower()

    def test_invalid_email_format(self):
        """Test validate_email with invalid format"""
        from app import validate_email
        is_valid, error_msg = validate_email('invalid.email')
        assert is_valid is False
        assert 'invalid' in error_msg.lower()

    def test_email_without_domain(self):
        """Test validate_email without domain"""
        from app import validate_email
        is_valid, error_msg = validate_email('test@')
        assert is_valid is False

    def test_email_with_plus(self):
        """Test validate_email with plus sign (valid)"""
        from app import validate_email
        is_valid, error_msg = validate_email('test+tag@example.com')
        assert is_valid is True


class TestValidatePassword:
    """Test cases for validate_password function"""
    
    def test_valid_password(self):
        """Test validate_password with valid password"""
        from app import validate_password
        is_valid, error_msg = validate_password('validpass123')
        assert is_valid is True
        assert error_msg is None

    def test_too_short_password(self):
        """Test validate_password with too short password"""
        from app import validate_password
        is_valid, error_msg = validate_password('12345')
        assert is_valid is False
        assert '6' in error_msg

    def test_empty_password(self):
        """Test validate_password with empty password"""
        from app import validate_password
        is_valid, error_msg = validate_password('')
        assert is_valid is False
        assert 'empty' in error_msg.lower()

    def test_too_long_password(self):
        """Test validate_password with too long password"""
        from app import validate_password
        is_valid, error_msg = validate_password('a' * 101)
        assert is_valid is False

    def test_minimum_length_password(self):
        """Test validate_password with minimum acceptable length"""
        from app import validate_password
        is_valid, error_msg = validate_password('123456')
        assert is_valid is True


class TestSanitizeInput:
    """Test cases for sanitize_input function"""
    
    def test_sanitize_removes_html(self):
        """Test sanitize_input removes HTML tags"""
        from app import sanitize_input
        result = sanitize_input('<script>alert("xss")</script>Test')
        assert '<script>' not in result
        assert 'alert' not in result
        assert 'Test' in result

    def test_sanitize_strips_whitespace(self):
        """Test sanitize_input strips whitespace"""
        from app import sanitize_input
        result = sanitize_input('  Test Input  ')
        assert result == 'Test Input'

    def test_sanitize_empty_string(self):
        """Test sanitize_input with empty string"""
        from app import sanitize_input
        result = sanitize_input('')
        assert result == ''

    def test_sanitize_removes_script_tags(self):
        """Test sanitize_input removes script tags"""
        from app import sanitize_input
        result = sanitize_input('Hello <script>malicious</script> World')
        assert 'script' not in result.lower()
        assert 'Hello' in result
        assert 'World' in result


class TestCheckSQLInjection:
    """Test cases for check_sql_injection_patterns function"""
    
    def test_valid_input_no_injection(self):
        """Test check_sql_injection_patterns with valid input"""
        from app import check_sql_injection_patterns
        result = check_sql_injection_patterns('John Doe')
        assert result is False

    def test_detects_or_statement(self):
        """Test check_sql_injection_patterns detects OR statements"""
        from app import check_sql_injection_patterns
        result = check_sql_injection_patterns("' OR '1'='1")
        assert result is True

    def test_detects_drop_table(self):
        """Test check_sql_injection_patterns detects DROP TABLE"""
        from app import check_sql_injection_patterns
        result = check_sql_injection_patterns("DROP TABLE users")
        assert result is True

    def test_detects_union_select(self):
        """Test check_sql_injection_patterns detects UNION SELECT"""
        from app import check_sql_injection_patterns
        result = check_sql_injection_patterns("UNION SELECT * FROM passwords")
        assert result is True

    def test_detects_insert_into(self):
        """Test check_sql_injection_patterns detects INSERT INTO"""
        from app import check_sql_injection_patterns
        result = check_sql_injection_patterns("INSERT INTO users VALUES (1, 'admin')")
        assert result is True

    def test_detects_delete_from(self):
        """Test check_sql_injection_patterns detects DELETE FROM"""
        from app import check_sql_injection_patterns
        result = check_sql_injection_patterns("DELETE FROM users")
        assert result is True

    def test_empty_input_is_safe(self):
        """Test check_sql_injection_patterns with empty input"""
        from app import check_sql_injection_patterns
        result = check_sql_injection_patterns('')
        assert result is False


# ============ ROUTE TESTS ============

class TestHomeRoute:
    """Test cases for home route"""
    
    def test_hello_world(self, client):
        """Test the home page route"""
        response = client.get('/')
        assert response.status_code == 200


class TestRegisterRoute:
    """Test cases for user registration"""
    
    def test_register_success(self, client):
        """Test successful user registration"""
        response = client.post('/register', data={
            'fname': 'Jane',
            'lname': 'Smith',
            'email': 'jane@example.com',
            'password': 'password123'
        })
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'successfully' in data['message'].lower()

    def test_register_empty_firstname(self, client):
        """Test registration with empty first name"""
        response = client.post('/register', data={
            'fname': '',
            'lname': 'Smith',
            'email': 'jane@example.com',
            'password': 'password123'
        })
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'empty' in data['message'].lower()

    def test_register_invalid_email(self, client):
        """Test registration with invalid email"""
        response = client.post('/register', data={
            'fname': 'Jane',
            'lname': 'Smith',
            'email': 'invalid.email',
            'password': 'password123'
        })
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'email' in data['message'].lower()

    def test_register_short_password(self, client):
        """Test registration with short password"""
        response = client.post('/register', data={
            'fname': 'Jane',
            'lname': 'Smith',
            'email': 'jane@example.com',
            'password': '12345'
        })
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'password' in data['message'].lower()

    def test_register_duplicate_email(self, client, sample_user):
        """Test registration with duplicate email"""
        response = client.post('/register', data={
            'fname': 'Jane',
            'lname': 'Smith',
            'email': 'john@example.com',
            'password': 'password123'
        })
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'already' in data['message'].lower()

    def test_register_sql_injection_attempt(self, client):
        """Test registration with SQL injection attempt"""
        response = client.post('/register', data={
            'fname': "' OR '1'='1",
            'lname': 'Smith',
            'email': 'jane@example.com',
            'password': 'password123'
        })
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'invalid' in data['message'].lower()

    def test_register_with_hyphens_in_name(self, client):
        """Test registration with hyphens in name"""
        response = client.post('/register', data={
            'fname': 'Mary-Jane',
            'lname': 'Smith',
            'email': 'mj@example.com',
            'password': 'password123'
        })
        data = json.loads(response.data)
        assert data['success'] is True


class TestGetUsersRoute:
    """Test cases for retrieving users"""
    
    def test_get_users(self, client, sample_user):
        """Test retrieving all users"""
        response = client.get('/api/users')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert len(data['data']) > 0
        assert data['data'][0]['fname'] == 'John'

    def test_get_users_password_hidden(self, client, sample_user):
        """Test that password is hidden when retrieving users"""
        response = client.get('/api/users')
        data = json.loads(response.data)
        assert '••••••' in data['data'][0]['password']

    def test_get_users_empty_database(self, client):
        """Test retrieving users from empty database"""
        response = client.get('/api/users')
        data = json.loads(response.data)
        assert data['success'] is True
        assert len(data['data']) == 0


class TestUpdateUserRoute:
    """Test cases for updating users"""
    
    def test_update_user_success(self, client, sample_user):
        """Test successful user update"""
        response = client.put('/api/users/1', 
            data=json.dumps({'fname': 'Jane'}),
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert data['success'] is True
        
        # Verify the update
        with app.app_context():
            user = User.query.get(1)
            assert user.fname == 'Jane'

    def test_update_user_not_found(self, client):
        """Test update non-existent user"""
        response = client.put('/api/users/999', 
            data=json.dumps({'fname': 'Jane'}),
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'not found' in data['message'].lower()

    def test_update_user_invalid_email(self, client, sample_user):
        """Test update user with invalid email"""
        response = client.put('/api/users/1', 
            data=json.dumps({'email': 'invalid.email'}),
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'email' in data['message'].lower()

    def test_update_user_duplicate_email(self, client, sample_user):
        """Test update user with duplicate email"""
        # Create another user
        with app.app_context():
            user2 = User(fname='Jane', lname='Doe', email='jane@example.com', password='pass')
            db.session.add(user2)
            db.session.commit()
        
        # Try to update first user with second user's email
        response = client.put('/api/users/1', 
            data=json.dumps({'email': 'jane@example.com'}),
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'already' in data['message'].lower()

    def test_update_user_password(self, client, sample_user):
        """Test updating user password"""
        response = client.put('/api/users/1', 
            data=json.dumps({'password': 'newpassword123'}),
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert data['success'] is True
        
        # Verify password is hashed
        with app.app_context():
            user = User.query.get(1)
            assert user.password != 'newpassword123'

    def test_update_user_multiple_fields(self, client, sample_user):
        """Test updating multiple user fields"""
        response = client.put('/api/users/1', 
            data=json.dumps({
                'fname': 'Jane',
                'lname': 'Doe',
                'email': 'jane.doe@example.com'
            }),
            content_type='application/json'
        )
        data = json.loads(response.data)
        assert data['success'] is True
        
        with app.app_context():
            user = User.query.get(1)
            assert user.fname == 'Jane'
            assert user.lname == 'Doe'
            assert user.email == 'jane.doe@example.com'


class TestDeleteUserRoute:
    """Test cases for deleting users"""
    
    def test_delete_user_success(self, client, sample_user):
        """Test successful user deletion"""
        response = client.delete('/api/users/1')
        data = json.loads(response.data)
        assert data['success'] is True
        
        # Verify deletion
        with app.app_context():
            user = User.query.get(1)
            assert user is None

    def test_delete_user_not_found(self, client):
        """Test delete non-existent user"""
        response = client.delete('/api/users/999')
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'not found' in data['message'].lower()


# ============ DATABASE MODEL TESTS ============

class TestUserModel:
    """Test cases for User model"""
    
    def test_user_model_creation(self, client):
        """Test User model can be created"""
        with app.app_context():
            user = User(
                fname='Test',
                lname='User',
                email='test@example.com',
                password='hashedpass'
            )
            db.session.add(user)
            db.session.commit()
            
            retrieved = User.query.filter_by(email='test@example.com').first()
            assert retrieved.fname == 'Test'
            assert retrieved.lname == 'User'

    def test_user_model_password_hashing(self, client):
        """Test that password is stored as hashed"""
        response = client.post('/register', data={
            'fname': 'Test',
            'lname': 'User',
            'email': 'test@example.com',
            'password': 'mypassword123'
        })
        
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            # Password should be hashed, not plain text
            assert user.password != 'mypassword123'
            # Verify it can be checked
            assert check_password_hash(user.password, 'mypassword123')

    def test_user_model_all_fields(self, client):
        """Test User model stores all fields correctly"""
        with app.app_context():
            user = User(
                fname='John',
                lname='Doe',
                email='john@test.com',
                password='pass123'
            )
            db.session.add(user)
            db.session.commit()
            
            retrieved = User.query.get(user.sno)
            assert retrieved.fname == 'John'
            assert retrieved.lname == 'Doe'
            assert retrieved.email == 'john@test.com'
            assert retrieved.password == 'pass123'


# ============ INTEGRATION TESTS ============

class TestIntegration:
    """Integration tests for complete workflows"""
    
    def test_complete_user_lifecycle(self, client):
        """Test complete user lifecycle: register, retrieve, update, delete"""
        # Register
        response = client.post('/register', data={
            'fname': 'John',
            'lname': 'Doe',
            'email': 'john@example.com',
            'password': 'password123'
        })
        assert json.loads(response.data)['success'] is True
        
        # Get users
        response = client.get('/api/users')
        data = json.loads(response.data)
        assert len(data['data']) == 1
        
        # Update
        response = client.put('/api/users/1', 
            data=json.dumps({'fname': 'Jane'}),
            content_type='application/json'
        )
        assert json.loads(response.data)['success'] is True
        
        # Delete
        response = client.delete('/api/users/1')
        assert json.loads(response.data)['success'] is True
        
        # Verify empty
        response = client.get('/api/users')
        assert len(json.loads(response.data)['data']) == 0

    def test_multiple_users_operations(self, client):
        """Test operations with multiple users"""
        # Create 3 users
        for i in range(3):
            response = client.post('/register', data={
                'fname': f'User{i}',
                'lname': 'Test',
                'email': f'user{i}@example.com',
                'password': 'password123'
            })
            assert json.loads(response.data)['success'] is True
        
        # Verify all users exist
        response = client.get('/api/users')
        data = json.loads(response.data)
        assert len(data['data']) == 3
