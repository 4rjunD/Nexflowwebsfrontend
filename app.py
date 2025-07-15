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
    hash_id = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_pro = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # New fields for B2B
    role = db.Column(db.String(20), nullable=False, default='patient')  # 'patient' or 'clinician'
    clinician_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # For patients: their clinician
    pending_clinician_invite = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # For patients: pending invite from clinician

# Add a new model for IRScore data
class IRScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash_id = db.Column(db.String(64), db.ForeignKey('user.hash_id'), nullable=False)
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

# New model for clinician codes
class ClinicianCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(6), unique=True, nullable=False)
    used = db.Column(db.Boolean, default=False)
    used_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(hash_id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'Token is invalid!'}), 401
            return f(current_user, *args, **kwargs)
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
    return decorated

# @app.before_request
# def handle_options():
#     if request.method == 'OPTIONS':
#         return '', 204

# # HTTPS enforcement
# @app.before_request
# def enforce_https():
#     if not request.is_secure and not app.debug and not app.testing:
#         if request.method == 'OPTIONS':
#             return '', 204  # Allow preflight through
#         elif request.method == 'GET':
#             url = request.url.replace('http://', 'https://', 1)
#             return '', 301, {'Location': url}
#         else:
#             return jsonify({'message': 'HTTPS required'}), 403


# CSRF protection: double submit cookie
CSRF_COOKIE_NAME = 'csrf_token'
CSRF_HEADER_NAME = 'X-CSRF-Token'

# @app.before_request
# def csrf_protect():
#     if request.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and request.path.startswith('/api/'):
#         csrf_token_cookie = request.cookies.get(CSRF_COOKIE_NAME)
#         csrf_token_header = request.headers.get(CSRF_HEADER_NAME)
#         if not csrf_token_cookie or not csrf_token_header:
#             return jsonify({'message': 'Missing CSRF token'}), 403
#         if csrf_token_cookie != csrf_token_header:
#             return jsonify({'message': 'Invalid CSRF token'}), 403

@app.before_request
def global_before_request():
    # Handle OPTIONS preflight
    if request.method == 'OPTIONS':
        return '', 204

    # Enforce HTTPS
    if not request.is_secure and not app.debug and not app.testing:
        if request.method == 'GET':
            url = request.url.replace('http://', 'https://', 1)
            return '', 301, {'Location': url}
        else:
            return jsonify({'message': 'HTTPS required'}), 403

    # CSRF protection
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and request.path.startswith('/api/'):
        csrf_token_cookie = request.cookies.get('csrf_token')
        csrf_token_header = request.headers.get('X-CSRF-Token')
        if not csrf_token_cookie or not csrf_token_header:
            return jsonify({'message': 'Missing CSRF token'}), 403
        if csrf_token_cookie != csrf_token_header:
            return jsonify({'message': 'Invalid CSRF token'}), 403



# Helper function to generate unique hash_id
def generate_hash_id():
    while True:
        hash_id = secrets.token_urlsafe(32)
        if not User.query.filter_by(hash_id=hash_id).first():
            return hash_id

# Helper to set CSRF cookie
@app.after_request
def set_csrf_cookie(response):
    # Only touch CSRF cookie if path is session or root (GET-only setup)
    if request.method == 'GET' and request.path in ['/', '/api/session']:
        if not request.cookies.get(CSRF_COOKIE_NAME):
            csrf_token = secrets.token_urlsafe(32)
            response.set_cookie(
                CSRF_COOKIE_NAME, csrf_token,
                httponly=False,
                secure=True,
                samesite='None',
                max_age=86400,
                path='/'
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

    # Role selection
    role = data.get('role', 'patient')
    if role not in ['patient', 'clinician']:
        return jsonify({'message': 'Invalid role'}), 400

    # Clinician signup: require and validate code
    if role == 'clinician':
        code = data.get('clinician_code')
        if not code:
            return jsonify({'message': 'Clinician code required'}), 400
        code_obj = ClinicianCode.query.filter_by(code=code, used=False).first()
        if not code_obj:
            return jsonify({'message': 'Invalid or already used clinician code'}), 400

    # Generate unique hash_id
    hash_id = generate_hash_id()
    
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        hash_id=hash_id,
        name=data['name'],
        email=data['email'],
        password=hashed_password,
        is_pro=data['plan'] == "pro",
        role=role
    )
    db.session.add(new_user)
    db.session.flush()  # Get new_user.id before commit

    # If clinician, mark code as used
    if role == 'clinician':
        code_obj.used = True
        code_obj.used_by = new_user.id
        db.session.add(code_obj)

    db.session.commit()
    
    # Generate JWT token for the new user
    token = jwt.encode({
        'user_id': new_user.hash_id,
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
        'user_id': user.hash_id,
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }, app.config['JWT_SECRET_KEY'])
    
    response = jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.hash_id,
            'name': user.name,
            'email': user.email,
            'is_pro': user.is_pro
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
        samesite='None',
        path='/'
    )
    response.delete_cookie(
        'csrf_token',
        httponly=False,
        secure=True,
        samesite='None',
        path='/'
    )
    return response

@app.route('/api/session', methods=['GET'])
def session_status():
    token = request.cookies.get('token')
    csrf_token = request.cookies.get(CSRF_COOKIE_NAME)

    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)

    resp = {
        "authenticated": False,
        "plan": None,
        "csrf_token": csrf_token
    }

    try:
        if not token:
            raise Exception("No token")
        data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        user = User.query.filter_by(hash_id=data['user_id']).first()
        if not user:
            raise Exception("Invalid user")
        plan = "pro" if user.is_pro else "free"
        resp["authenticated"] = True
        resp["plan"] = plan
    except Exception:
        pass

    # Send token as cookie (for fallback) AND JSON
    response = jsonify(resp)
    response.set_cookie(
        CSRF_COOKIE_NAME, csrf_token,
        httponly=False,
        secure=True,
        samesite='None',
        max_age=86400
    )
    return response





@app.route('/api/user', methods=['GET'])
@token_required
def get_user(current_user):
    return jsonify({
        'id': current_user.hash_id,
        'name': current_user.name,
        'email': current_user.email,
        'is_pro': current_user.is_pro
    })



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
        hash_id=current_user.hash_id,
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
    irscore = IRScore.query.filter_by(hash_id=current_user.hash_id).order_by(IRScore.created_at.desc()).first()
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
        user = User.query.filter_by(hash_id=data['user_id']).first()
        if not user:
            return jsonify({'message': 'Invalid refresh token'}), 401
        # Issue new access token
        access_token = jwt.encode({
            'user_id': user.hash_id,
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

@app.route('/api/clinician/invite', methods=['POST'])
@token_required
def clinician_invite(current_user):
    if current_user.role != 'clinician':
        return jsonify({'message': 'Only clinicians can send invites'}), 403
    data = request.get_json()
    patient_email = data.get('email')
    if not patient_email:
        return jsonify({'message': 'Patient email required'}), 400
    patient = User.query.filter_by(email=patient_email, role='patient').first()
    if not patient:
        return jsonify({'message': 'No patient found with that email'}), 404
    if patient.clinician_id == current_user.id:
        return jsonify({'message': 'Patient is already linked to you'}), 400
    if patient.pending_clinician_invite == current_user.id:
        return jsonify({'message': 'Invite already pending for this patient'}), 400
    patient.pending_clinician_invite = current_user.id
    db.session.commit()
    return jsonify({'message': 'Invite sent successfully'})

@app.route('/api/patient/invite-status', methods=['GET'])
@token_required
def patient_invite_status(current_user):
    if current_user.role != 'patient':
        return jsonify({'message': 'Only patients can check invites'}), 403
    if current_user.pending_clinician_invite:
        clinician = User.query.get(current_user.pending_clinician_invite)
        if clinician:
            return jsonify({'pending': True, 'clinician_name': clinician.name, 'clinician_email': clinician.email})
    return jsonify({'pending': False})

@app.route('/api/patient/respond-invite', methods=['POST'])
@token_required
def patient_respond_invite(current_user):
    if current_user.role != 'patient':
        return jsonify({'message': 'Only patients can respond to invites'}), 403
    data = request.get_json()
    action = data.get('action')  # 'accept' or 'reject'
    if not current_user.pending_clinician_invite:
        return jsonify({'message': 'No pending invite'}), 400
    if action == 'accept':
        current_user.clinician_id = current_user.pending_clinician_invite
        current_user.pending_clinician_invite = None
        db.session.commit()
        return jsonify({'message': 'Invite accepted'})
    elif action == 'reject':
        current_user.pending_clinician_invite = None
        db.session.commit()
        return jsonify({'message': 'Invite rejected'})
    else:
        return jsonify({'message': 'Invalid action'}), 400

@app.route('/api/clinician/patients', methods=['GET'])
@token_required
def clinician_patients(current_user):
    if current_user.role != 'clinician':
        return jsonify({'message': 'Only clinicians can access this'}), 403
    # Query params: search, risk
    search = request.args.get('search', '').strip().lower()
    risk = request.args.get('risk')  # 'excellent', 'good', 'moderate', 'high'
    # Get all patients linked to this clinician
    patients = User.query.filter_by(clinician_id=current_user.id, role='patient').all()
    # Get latest IRScore for each patient
    result = []
    for patient in patients:
        irscore_obj = IRScore.query.filter_by(hash_id=patient.hash_id).order_by(IRScore.created_at.desc()).first()
        irscore = irscore_obj.score if irscore_obj else None
        # Risk level logic (from irscore.html)
        if irscore is not None:
            if irscore >= 81.8:
                risk_level = 'excellent'
            elif irscore >= 71.1:
                risk_level = 'good'
            elif irscore >= 35.4:
                risk_level = 'moderate'
            else:
                risk_level = 'high'
        else:
            risk_level = 'unknown'
        # Search filter
        if search and search not in patient.name.lower() and (irscore is None or search not in str(irscore)):
            continue
        # Risk filter
        if risk and risk_level != risk:
            continue
        result.append({
            'id': patient.hash_id,
            'name': patient.name,
            'email': patient.email,
            'irscore': irscore,
            'risk_level': risk_level
        })
    return jsonify(result)

@app.route('/api/clinician/patient/<patient_id>', methods=['GET'])
@token_required
def clinician_patient_detail(current_user, patient_id):
    if current_user.role != 'clinician':
        return jsonify({'message': 'Only clinicians can access this'}), 403
    patient = User.query.filter_by(hash_id=patient_id, role='patient', clinician_id=current_user.id).first()
    if not patient:
        return jsonify({'message': 'Patient not found or not linked to you'}), 404
    irscores = IRScore.query.filter_by(hash_id=patient.hash_id).order_by(IRScore.created_at.desc()).all()
    irscore_data = [
        {
            'score': ir.score,
            'created_at': ir.created_at.isoformat(),
            'age': ir.age,
            'gender': ir.gender,
            'weight': ir.weight,
            'height': ir.height,
            'bmi': ir.bmi,
            'sleep': ir.sleep,
            'family_history': ir.family_history,
            'activity': ir.activity
        }
        for ir in irscores
    ]
    return jsonify({
        'id': patient.hash_id,
        'name': patient.name,
        'email': patient.email,
        'irscore_history': irscore_data
    })

@app.route('/api/clinician/irscore-distribution', methods=['GET'])
@token_required
def clinician_irscore_distribution(current_user):
    if current_user.role != 'clinician':
        return jsonify({'message': 'Only clinicians can access this'}), 403
    # Get all patients linked to this clinician
    patients = User.query.filter_by(clinician_id=current_user.id, role='patient').all()
    # Get latest IRScore for each patient
    bins = {
        'excellent': 0,
        'good': 0,
        'moderate': 0,
        'high': 0,
        'unknown': 0
    }
    for patient in patients:
        irscore_obj = IRScore.query.filter_by(hash_id=patient.hash_id).order_by(IRScore.created_at.desc()).first()
        irscore = irscore_obj.score if irscore_obj else None
        if irscore is not None:
            if irscore >= 81.8:
                bins['excellent'] += 1
            elif irscore >= 71.1:
                bins['good'] += 1
            elif irscore >= 35.4:
                bins['moderate'] += 1
            else:
                bins['high'] += 1
        else:
            bins['unknown'] += 1
    return jsonify(bins)

@app.route('/api/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    return '', 204


# Create database tables and seed clinician codes
with app.app_context():
    db.create_all()
    # Seed clinician codes if not present
    if ClinicianCode.query.count() == 0:
        import random
        codes = set()
        while len(codes) < 50:
            code = f"{random.randint(0, 999999):06d}"
            codes.add(code)
        for code in codes:
            db.session.add(ClinicianCode(code=code))
        db.session.commit()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port) 