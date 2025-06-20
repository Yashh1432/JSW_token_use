# views.py
from pymongo import MongoClient
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import uuid
from cryptography.fernet import Fernet
from functools import wraps
from django.conf import settings
import base64
import bson

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['jwt_auth_db']
users_collection = db['users']
audit_collection = db['audit']
data_collection = db['data']

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Encryption key for data
ENCRYPTION_KEY = settings.ENCRYPTION_KEY.encode()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Helper function to verify JWT token
def verify_token(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, JsonResponse({'error': 'Invalid token'}, status=401)
    
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload['sub'], None
    except JWTError:
        return None, JsonResponse({'error': 'Invalid token'}, status=401)

# Decorator to require login
def login_required(f):
    @wraps(f)
    def decorated_function(request, *args, **kwargs):
        email, error_response = verify_token(request)
        if error_response:
            return error_response
        request.user_email = email
        return f(request, *args, **kwargs)
    return decorated_function

# Helper function to log audit
def log_audit(action, user_id, query_params):
    audit_collection.insert_one({
        'action': action,
        'user_id': user_id,
        'timestamp': datetime.utcnow(),
        'query_params': query_params
    })

# Data encryption/decryption helpers
def encrypt_data(data):
    if isinstance(data, dict):
        return {k: encrypt_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [encrypt_data(item) for item in data]
    elif isinstance(data, str):
        return cipher_suite.encrypt(data.encode()).decode()
    elif isinstance(data, bytes):
        return cipher_suite.encrypt(data).decode()
    elif isinstance(data, datetime):
        return cipher_suite.encrypt(data.isoformat().encode()).decode()
    # Leave integers, floats, booleans, and None unencrypted
    return data

def decrypt_data(data):
    if isinstance(data, dict):
        return {k: decrypt_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [decrypt_data(item) for item in data]
    elif isinstance(data, str):
        try:
            decrypted = cipher_suite.decrypt(data.encode()).decode()
            # Check if it's a datetime string
            try:
                return datetime.fromisoformat(decrypted)
            except ValueError:
                return decrypted
        except:
            return data
    # Return integers, floats, booleans, and None as-is
    return data

@csrf_exempt
def register(request):
    if request.method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    if request.method == 'GET':
        email = request.GET.get('email')
        if not email:
            return JsonResponse({'error': 'Email required'}, status=400)
        user = users_collection.find_one({'email': email}, {'_id': 0, 'password': 0})
        if not user:
            return JsonResponse({'error': 'User not found'}, status=404)
        
        log_audit('register_get', user.get('user_id', ''), dict(request.GET))
        return JsonResponse({'user': user}, status=200)

    try:
        data = json.loads(request.body) if request.body else {}
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    username = data.get('username', '')
    password = data.get('password')
    email = data.get('email')

    if request.method in ['POST', 'PUT', 'PATCH']:
        if not email or not password:
            return JsonResponse({'error': 'Email and password required'}, status=400)

        existing_user = users_collection.find_one({'email': email})

        if request.method == 'POST':
            if existing_user:
                return JsonResponse({'error': 'Email already exists'}, status=400)
            hashed_password = pwd_context.hash(password)
            user_id = str(uuid.uuid4())
            user = {
                'user_id': user_id,
                'username': username,
                'password': hashed_password,
                'email': email,
                'created_at': datetime.utcnow()
            }
            users_collection.insert_one(user)
            action = 'register_post'

        elif request.method in ['PUT', 'PATCH']:
            if not existing_user:
                return JsonResponse({'error': 'User not found'}, status=404)
            update_data = {'username': username, 'email': email}
            if password:
                update_data['password'] = pwd_context.hash(password)
            update_data['updated_at'] = datetime.utcnow()
            users_collection.update_one({'email': email}, {'$set': update_data})
            action = f'register_{request.method.lower()}'

        log_audit(action, user_id if request.method == 'POST' else existing_user['user_id'], dict(request.GET))
        return JsonResponse({'message': f'User {request.method.lower()}ed successfully'}, status=200)

    elif request.method == 'DELETE':
        if not email:
            return JsonResponse({'error': 'Email required'}, status=400)
        existing_user = users_collection.find_one({'email': email})
        if not existing_user:
            return JsonResponse({'error': 'User not found'}, status=404)
        users_collection.delete_one({'email': email})
        
        log_audit('register_delete', existing_user['user_id'], dict(request.GET))
        return JsonResponse({'message': 'User deleted'}, status=200)

@csrf_exempt
def login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return JsonResponse({'error': 'Email and password required'}, status=400)

        user = users_collection.find_one({'email': email})
        if not user or not pwd_context.verify(password, user['password']):
            log_audit('login_failed', user['user_id'] if user else '', dict(request.GET))
            return JsonResponse({'error': 'Invalid credentials'}, status=401)

        token = jwt.encode({
            'sub': email,
            'user_id': user['user_id'],
            'exp': datetime.utcnow() + timedelta(seconds=settings.JWT_EXPIRATION_DELTA)
        }, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

        log_audit('login', user['user_id'], dict(request.GET))
        return JsonResponse({'token': token}, status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def logout(request):
    if request.method == 'POST':
        email, error_response = verify_token(request)
        if error_response:
            log_audit('logout_failed', '', dict(request.GET))
            return error_response
            
        user = users_collection.find_one({'email': email})
        log_audit('logout', user['user_id'] if user else '', dict(request.GET))
        return JsonResponse({'message': 'Logged out'}, status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
@login_required
def data_operations(request):
    if request.method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    user = users_collection.find_one({'email': request.user_email})
    if not user:
        return JsonResponse({'error': 'User not found'}, status=404)

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        # Convert binary data if present
        if 'binary_data' in data:
            data['binary_data'] = base64.b64decode(data['binary_data'])

        data_id = str(uuid.uuid4())
        encrypted_data = encrypt_data(data)
        data_document = {
            'data_id': data_id,
            'user_id': user['user_id'],
            'data': encrypted_data,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        data_collection.insert_one(data_document)
        log_audit('data_create', user['user_id'], dict(request.GET))
        return JsonResponse({'message': 'Data created', 'data_id': data_id}, status=201)

    elif request.method == 'GET':
        data_id = request.GET.get('data_id')
        query = {'user_id': user['user_id']}
        if data_id:
            query['data_id'] = data_id

        data_items = list(data_collection.find(query, {'_id': 0}))
        decrypted_items = []
        for item in data_items:
            decrypted_data = decrypt_data(item['data'])
            # Only encode binary_data if it's bytes; otherwise, assume it's already base64
            if 'binary_data' in decrypted_data and isinstance(decrypted_data['binary_data'], bytes):
                decrypted_data['binary_data'] = base64.b64encode(decrypted_data['binary_data']).decode()
            decrypted_items.append({
                'data_id': item['data_id'],
                'data': decrypted_data,
                'created_at': item['created_at'],
                'updated_at': item['updated_at']
            })
        log_audit('data_read', user['user_id'], dict(request.GET))
        return JsonResponse({'data': decrypted_items}, status=200)

    elif request.method in ['PUT', 'PATCH']:
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        data_id = data.get('data_id')
        if not data_id:
            return JsonResponse({'error': 'Data ID required'}, status=400)

        existing_data = data_collection.find_one({'data_id': data_id, 'user_id': user['user_id']})
        if not existing_data:
            return JsonResponse({'error': 'Data not found or unauthorized'}, status=404)

        # Convert binary data if present
        if 'binary_data' in data['data']:
            data['data']['binary_data'] = base64.b64decode(data['data']['binary_data'])

        encrypted_data = encrypt_data(data.get('data', {}))
        update_data = {
            'data': encrypted_data,
            'updated_at': datetime.utcnow()
        }
        data_collection.update_one({'data_id': data_id}, {'$set': update_data})
        log_audit(f'data_{request.method.lower()}', user['user_id'], dict(request.GET))
        return JsonResponse({'message': 'Data updated'}, status=200)

    elif request.method == 'DELETE':
        data_id = request.GET.get('data_id')
        if not data_id:
            return JsonResponse({'error': 'Data ID required'}, status=400)

        result = data_collection.delete_one({'data_id': data_id, 'user_id': user['user_id']})
        if result.deleted_count == 0:
            return JsonResponse({'error': 'Data not found or unauthorized'}, status=404)

        log_audit('data_delete', user['user_id'], dict(request.GET))
        return JsonResponse({'message': 'Data deleted'}, status=200)

@csrf_exempt
def get_audit_logs(request):
    if request.method == 'GET':
        filters = dict(request.GET)
        query = {}
        if 'user_id' in filters:
            query['user_id'] = filters['user_id']
        if 'action' in filters:
            query['action'] = filters['action']

        logs = list(audit_collection.find(query, {'_id': 0}))
        return JsonResponse({'logs': logs}, status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)