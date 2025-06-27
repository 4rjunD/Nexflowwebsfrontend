from flask import Flask, request, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import jwt
from functools import wraps
from sqlalchemy import text
import numpy as np
from api.backend.inference import calculate_irscore
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets

app = Flask(__name__, static_folder='.', static_url_path='')

CORS(app,
     origins=["https://nexflowai.app"],
     supports_credentials=True,
     allow_headers=["Content-Type", "X-CSRF-Token"],
     methods=["GET", "POST", "OPTIONS"])

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', os.urandom(24))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7)

# Handle SQLite database URL for production
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

db = SQLAlchemy(app)

# Flask-Limiter setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_pro = db.Column(db.Boolean, default=False)
    demo_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Add a new model for IRScore data
class IRScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.Integer)
    weight = db.Column(db.Float)
    height = db.Column(db.Float)
    bmi = db.Column(db.Float)
    sleep = db.Column(db.String(100))
    family_history = db.Column(db.String(100))
    activity = db.Column(db.String(100))
    score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        return '', 204

# HTTPS enforcement
@app.before_request
def enforce_https():
    if not request.is_secure and not app.debug and not app.testing:
        if request.method == 'OPTIONS':
            return '', 204  # Allow preflight through
        elif request.method == 'GET':
            url = request.url.replace('http://', 'https://', 1)
            return '', 301, {'Location': url}
        else:
            return jsonify({'message': 'HTTPS required'}), 403


# CSRF protection: double submit cookie
CSRF_COOKIE_NAME = 'csrf_token'
CSRF_HEADER_NAME = 'X-CSRF-Token'

@app.before_request
def csrf_protect():
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and request.path.startswith('/api/'):
        # Exclude login and signup GETs, but protect POSTs
        csrf_token_cookie = request.cookies.get(CSRF_COOKIE_NAME)
        csrf_token_header = request.headers.get(CSRF_HEADER_NAME)
        if not csrf_token_cookie or not csrf_token_header or csrf_token_cookie != csrf_token_header:
            return jsonify({'message': 'Missing or invalid CSRF token'}), 403

# Helper to set CSRF cookie
@app.after_request
def set_csrf_cookie(response):
    if request.method == 'GET' and not request.cookies.get(CSRF_COOKIE_NAME):
        csrf_token = secrets.token_urlsafe(32)
        response.set_cookie(
            CSRF_COOKIE_NAME, csrf_token,
            httponly=False,
            secure=True,
            samesite='None',
            max_age=60*60*24,
            path='/api/'
        )
    return response

@app.route('/api/csrf', methods=['GET'])
def get_csrf():
    token = secrets.token_urlsafe(32)
    resp = jsonify({'csrf_token': token})
    resp.set_cookie(
        CSRF_COOKIE_NAME, token,
        httponly=False,  # must be JS-readable
        secure=True,
        samesite='None',
        max_age=86400
    )
    return resp


# Serve static files
@app.route('/')
def serve_index():
    return jsonify({"message": "Backend server is running"})

@app.route('/test')
def test():
    return jsonify({"message": "Test endpoint is working"})

@app.route('/<path:path>')
def serve_static(path):
    if path.startswith("api/"):
        return jsonify({"error": "Not Found"}), 404
    return send_from_directory('.', path)

# API Routes
@app.route('/api/signup', methods=['POST', 'OPTIONS'])
@limiter.limit('5 per minute')
def signup():
    data = request.get_json()
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400
    
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        name=data['name'],
        email=data['email'],
        password=hashed_password,
        is_pro=data['plan'] == "pro"
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    # Generate JWT token for the new user
    token = jwt.encode({
        'user_id': new_user.id,
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }, app.config['JWT_SECRET_KEY'], algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    
    resp = jsonify({'message': 'User created successfully'})
    resp.set_cookie(
        'token', token,
        httponly=True,
        secure=True,  # Only over HTTPS in production!
        samesite='None'
    )
    return resp, 201

@app.route('/api/predict', methods=['POST'])
@limiter.limit('20 per minute')
def predict():
    data = request.get_json()
    x = np.array([[data['age'], data['gender'], data['bmi'], data['weight'], data['height']]])
    score = calculate_irscore(x)
    return jsonify({"score": score})

@app.route('/api/login', methods=['POST'])
@limiter.limit('10 per minute')
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'message': 'Invalid email or password'}), 401
    
    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }, app.config['JWT_SECRET_KEY'])
    
    response = jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'is_pro': user.is_pro,
            'demo_used': user.demo_used
        }
    })
    
    response.set_cookie(
        'token',
        token,
        httponly=True,
        secure=True,
        samesite='None',
        max_age=86400
    )
    
    return response

@app.route('/api/logout', methods=['POST'])
def logout():
    response = jsonify({'message': 'Logged out successfully'})
    response.delete_cookie(
        'token',
        httponly=True,
        secure=True,
        samesite='None'
    )
    return response

@app.route('/api/session', methods=['GET'])
def session_status():
    csrf_token = secrets.token_urlsafe(32)
    token = request.cookies.get('token')

    # Default values
    authenticated = False
    plan = None

    if token:
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            user = User.query.get(data['user_id'])
            if user:
                authenticated = True
                plan = "pro" if user.is_pro else "free"
        except Exception:
            pass  # Invalid token, fallback to unauthenticated

    resp = jsonify({"authenticated": authenticated, "plan": plan})
    resp.set_cookie(
        CSRF_COOKIE_NAME, csrf_token,
        httponly=False,
        secure=True,
        samesite='None',
        max_age=60*60*24
    )
    return resp



@app.route('/api/user', methods=['GET'])
@token_required
def get_user(current_user):
    return jsonify({
        'id': current_user.id,
        'name': current_user.name,
        'email': current_user.email,
        'is_pro': current_user.is_pro,
        'demo_used': current_user.demo_used
    })

@app.route('/api/use-demo', methods=['POST'])
@token_required
def use_demo(current_user):
    if current_user.demo_used:
        return jsonify({'message': 'Demo already used'}), 400
    
    current_user.demo_used = True
    db.session.commit()
    
    return jsonify({'message': 'Demo marked as used'})

@app.route('/api/upgrade-to-pro', methods=['POST'])
@token_required
def upgrade_to_pro(current_user):
    # Here you would typically integrate with a payment processor
    # For now, we'll just mark the user as pro
    current_user.is_pro = True
    db.session.commit()
    
    return jsonify({'message': 'Upgraded to pro successfully'})

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Try to query the database
        db.session.execute(text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'database': 'connected'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e)
        }), 500

@app.route('/api/db-check', methods=['GET'])
def db_check():
    try:
        # Get database URL without credentials
        db_url = app.config['SQLALCHEMY_DATABASE_URI']
        if db_url.startswith('postgresql://'):
            # Mask the password in the URL
            masked_url = db_url.split('@')[0].split(':')
            if len(masked_url) > 2:
                masked_url[2] = '****'
            masked_url = ':'.join(masked_url) + '@' + db_url.split('@')[1]
        else:
            masked_url = 'sqlite:///users.db'  # Local development

        # Try to query the database
        db.session.execute('SELECT 1')
        
        # Try to get user count
        user_count = User.query.count()
        
        return jsonify({
            'status': 'connected',
            'database_type': 'postgresql' if 'postgresql' in db_url else 'sqlite',
            'database_url_masked': masked_url,
            'user_count': user_count,
            'tables_created': True
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'database_type': 'postgresql' if 'postgresql' in app.config['SQLALCHEMY_DATABASE_URI'] else 'sqlite'
        }), 500

# Endpoint to save IRScore data
@app.route('/api/irscore', methods=['POST'])
@token_required
def save_irscore(current_user):
    data = request.get_json()
    irscore = IRScore(
        user_id=current_user.id,
        age=data.get('age'),
        gender=data.get('gender'),
        weight=data.get('weight'),
        height=data.get('height'),
        bmi=data.get('bmi'),
        sleep=data.get('sleep'),
        family_history=data.get('family_history'),
        activity=data.get('activity'),
        score=data.get('score')
    )
    db.session.add(irscore)
    db.session.commit()
    return jsonify({'message': 'IRScore saved successfully'})

# Endpoint to fetch latest IRScore data
@app.route('/api/irscore', methods=['GET'])
@token_required
def get_irscore(current_user):
    irscore = IRScore.query.filter_by(user_id=current_user.id).order_by(IRScore.created_at.desc()).first()
    if not irscore:
        return jsonify({'message': 'No IRScore data found'}), 404
    return jsonify({
        'age': irscore.age,
        'gender': irscore.gender,
        'weight': irscore.weight,
        'height': irscore.height,
        'bmi': irscore.bmi,
        'sleep': irscore.sleep,
        'family_history': irscore.family_history,
        'activity': irscore.activity,
        'score': irscore.score,
        'created_at': irscore.created_at.isoformat()
    })

# JWT refresh token support
@app.route('/api/refresh', methods=['POST'])
def refresh_token():
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        return jsonify({'message': 'Missing refresh token'}), 401
    try:
        data = jwt.decode(refresh_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user = User.query.get(data['user_id'])
        if not user:
            return jsonify({'message': 'Invalid refresh token'}), 401
        # Issue new access token
        access_token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
        }, app.config['JWT_SECRET_KEY'], algorithm="HS256")
        if isinstance(access_token, bytes):
            access_token = access_token.decode('utf-8')
        resp = jsonify({'message': 'Token refreshed'})
        resp.set_cookie(
            'token', access_token,
            httponly=True,
            secure=True,
            samesite='None',
            max_age=30*60
        )
        return resp
    except Exception:
        return jsonify({'message': 'Invalid or expired refresh token'}), 401


@app.route('/api/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    return '', 204


# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port) 