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
import logging

# Configure logging
logger = logging.getLogger(__name__)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['jwt_auth']  # Database name
users_collection = db['users']
audit_collection = db['audit']
data_collection = db['data']
blacklist_collection = db['token_blacklist']  # For blacklisted tokens

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Encryption key for data
ENCRYPTION_KEY = settings.ENCRYPTION_KEY.encode()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Helper function to verify JWT token
def verify_token(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning("Invalid token: Missing or malformed Authorization header")
        return None, None, JsonResponse({'error': 'Invalid or missing token'}, status=401)
    
    token = auth_header.split(' ')[1]
    
    # Check if token is blacklisted
    if blacklist_collection.find_one({'token': token}):
        logger.warning(f"Token is blacklisted: {token}")
        return None, None, JsonResponse({'error': 'Token is invalid (blacklisted)'}, status=401)

    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        email = payload.get('sub')
        user_id = payload.get('user_id')
        if not email or not user_id:
            logger.warning("Invalid token: Missing email or user_id in payload")
            return None, None, JsonResponse({'error': 'Invalid token payload'}, status=401)
        return email, user_id, None
    except JWTError as e:
        logger.error(f"JWT decode error: {str(e)}")
        return None, None, JsonResponse({'error': f'Invalid token: {str(e)}'}, status=401)

# Decorator to require login
def login_required(f):
    @wraps(f)
    def decorated_function(request, *args, **kwargs):
        email, user_id, error_response = verify_token(request)
        if error_response:
            return error_response
        request.user_email = email
        request.user_id = user_id
        return f(request, *args, **kwargs)
    return decorated_function

# Helper function to log audit
def log_audit(action, user_id, query_params):
    try:
        audit_collection.insert_one({
            'action': str(action),
            'user_id': str(user_id) if user_id else '',
            'timestamp': datetime.utcnow(),
            'query_params': dict(query_params)
        })
        logger.debug(f"Audit logged: {action} by user_id {user_id}")
    except Exception as e:
        logger.error(f"Failed to log audit: {str(e)}")

# Data encryption/decryption helpers
def encrypt_data(data):
    if isinstance(data, dict):
        return {k: encrypt_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [encrypt_data(item) for item in data]
    elif isinstance(data, str):
        return cipher_suite.encrypt(data.encode()).hex()
    elif isinstance(data, bytes):
        return cipher_suite.encrypt(data).hex()
    elif isinstance(data, datetime):
        return cipher_suite.encrypt(data.isoformat().encode()).hex()
    return data

def decrypt_data(data):
    if isinstance(data, dict):
        return {k: decrypt_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [decrypt_data(item) for item in data]
    elif isinstance(data, str):
        try:
            decrypted = cipher_suite.decrypt(bytes.fromhex(data)).decode()
            try:
                return datetime.fromisoformat(decrypted)
            except ValueError:
                return decrypted
        except Exception as e:
            logger.warning(f"Decryption failed: {str(e)}")
            return data
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
        
        log_audit('register_get', user.get('_id', ''), dict(request.GET))
        return JsonResponse({'user': user}, status=200)

    try:
        data = json.loads(request.body) if request.body else {}
    except json.JSONDecodeError:
        logger.error("Invalid JSON in register request")
        return JsonResponse({'error': 'Invalid JSON'}, status=422)

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
                '_id': user_id,
                'username': username,
                'password': hashed_password,
                'email': email,
                'created_at': datetime.utcnow()
            }
            try:
                users_collection.insert_one(user)
            except Exception as e:
                logger.error(f"Failed to register user: {str(e)}")
                return JsonResponse({'error': 'Failed to create user'}, status=500)
            action = 'register_post'

        elif request.method in ['PUT', 'PATCH']:
            if not existing_user:
                return JsonResponse({'error': 'User not found'}, status=404)
            update_data = {'username': username, 'email': email}
            if password:
                update_data['password'] = pwd_context.hash(password)
            update_data['updated_at'] = datetime.utcnow()
            try:
                users_collection.update_one({'email': email}, {'$set': update_data})
            except Exception as e:
                logger.error(f"Failed to update user: {str(e)}")
                return JsonResponse({'error': 'Failed to update user'}, status=500)
            action = f'register_{request.method.lower()}'

        log_audit(action, user_id if request.method == 'POST' else existing_user['_id'], dict(request.GET))
        return JsonResponse({'message': f'User {request.method.lower()}ed successfully'}, status=200)

    elif request.method == 'DELETE':
        if not email:
            return JsonResponse({'error': 'Email required'}, status=400)
        existing_user = users_collection.find_one({'email': email})
        if not existing_user:
            return JsonResponse({'error': 'User not found'}, status=404)
        try:
            users_collection.delete_one({'email': email})
        except Exception as e:
            logger.error(f"Failed to delete user: {str(e)}")
            return JsonResponse({'error': 'Failed to delete user'}, status=500)
        
        log_audit('register_delete', existing_user['_id'], dict(request.GET))
        return JsonResponse({'message': 'User deleted'}, status=200)

@csrf_exempt
def login(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in login request: {str(e)}")
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return JsonResponse({'error': 'Email and password required'}, status=400)

    try:
        user = users_collection.find_one({'email': email})
    except Exception as e:
            logger.error(f"Failed to find user: {str(e)}")
            return JsonResponse({'error': 'Failed to fetch user'}, status=500)

    if not user or not pwd_context.verify(password, user['password']):
        log_audit('login_failed', user['_id'] if user else '', dict(request.GET))
        return JsonResponse({'error': 'Invalid credentials'}, status=401)

    token = jwt.encode({
        'sub': email,
        'user_id': user['_id'],
        'exp': datetime.utcnow() + timedelta(seconds=settings.JWT_EXPIRATION_DELTA)
    }, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    log_audit('login', user['_id'], dict(request.GET))
    return JsonResponse({'token': token}, status=200)

@csrf_exempt
def logout(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning("Missing Authorization header in logout request")
        return JsonResponse({'error': 'Invalid or missing token'}, status=401)

    token = auth_header.split(' ')[1]
    email, user_id, error_response = verify_token(request)
    if error_response:
        log_audit('logout_failed', user_id, dict(request.GET))
        return error_response

    try:
        blacklist_collection.insert_one({
            'token': token,
            'user_id': user_id,
            'blacklisted_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(seconds=settings.JWT_EXPIRATION_DELTA)
        })
        logger.info(f"Token blacklisted for user_id {user_id}")
    except Exception as e:
        logger.error(f"Failed to blacklist token: {str(e)}")
        return JsonResponse({'error': 'Failed to logout'}, status=500)

    log_audit('logout', user_id, dict(request.GET))
    return JsonResponse({'message': 'Logged out successfully'}, status=200)

@csrf_exempt
@login_required
def data_operations(request):
    if request.method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        user = users_collection.find_one({'_id': request.user_id, 'email': request.user_email})
    except Exception as e:
        logger.error(f"Failed to fetch user: {str(e)}")
        return JsonResponse({'error': 'Failed to fetch user'}, status=500)

    if not user:
        logger.warning(f"User not found: email={request.user_email}, user_id={request.user_id}")
        return JsonResponse({'error': 'User not found or unauthorized'}, status=404)

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in data_operations POST request: {str(e)}")
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        if 'binary_data' in data:
            try:
                data['binary_data'] = base64.b64decode(data['binary_data'])
            except Exception as e:
                logger.error(f"Invalid base64 data: {str(e)}")
                return JsonResponse({'error': 'Invalid binary_data format'}, status=400)

        data_id = str(uuid.uuid4())
        encrypted_data = encrypt_data(data)
        data_document = {
            '_id': data_id,
            'user_id': user['_id'],
            'data': encrypted_data,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        try:
            data_collection.insert_one(data_document)
        except Exception as e:
            logger.error(f"Failed to insert data: {str(e)}")
            return JsonResponse({'error': 'Failed to create data'}, status=500)
        log_audit('data_create', user['_id'], dict(request.GET))
        return JsonResponse({'message': 'Data created', 'data_id': data_id}, status=201)

    elif request.method == 'GET':
        data_id = request.GET.get('data_id')
        query = {'user_id': user['_id']}
        if data_id:
            query['_id'] = data_id

        try:
            data_items = list(data_collection.find(query))
        except Exception as e:
            logger.error(f"Failed to query data: {str(e)}")
            return JsonResponse({'error': 'Failed to retrieve data'}, status=500)

        decrypted_items = []
        for item in data_items:
            decrypted_data = decrypt_data(item['data'])
            if 'binary_data' in decrypted_data and isinstance(decrypted_data['binary_data'], bytes):
                decrypted_data['binary_data'] = base64.b64encode(decrypted_data['binary_data']).decode()
            decrypted_items.append({
                'data_id': item['_id'],
                'data': decrypted_data,
                'created_at': item['created_at'],
                'updated_at': item['updated_at']
            })
        log_audit('data_read', user['_id'], dict(request.GET))
        return JsonResponse({'data': decrypted_items}, status=200)

    elif request.method in ['PUT', 'PATCH']:
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in data_operations PUT/PATCH request: {str(e)}")
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        data_id = data.get('data_id')
        if not data_id:
            return JsonResponse({'error': 'Data ID required'}, status=400)

        try:
            existing_data = data_collection.find_one({'_id': data_id, 'user_id': user['_id']})
        except Exception as e:
            logger.error(f"Failed to query data: {str(e)}")
            return JsonResponse({'error': 'Failed to retrieve data'}, status=500)

        if not existing_data:
            return JsonResponse({'error': 'Data not found or unauthorized'}, status=404)

        if 'binary_data' in data['data']:
            try:
                data['data']['binary_data'] = base64.b64decode(data['data']['binary_data'])
            except Exception as e:
                logger.error(f"Invalid base64 data in update: {str(e)}")
                return JsonResponse({'error': 'Invalid binary_data format'}, status=400)

        encrypted_data = encrypt_data(data.get('data', {}))
        update_data = {
            'data': encrypted_data,
            'updated_at': datetime.utcnow()
        }
        try:
            data_collection.update_one({'_id': data_id}, {'$set': update_data})
        except Exception as e:
            logger.error(f"Failed to update data: {str(e)}")
            return JsonResponse({'error': 'Failed to update data'}, status=500)
        log_audit(f'data_{request.method.lower()}', user['_id'], dict(request.GET))
        return JsonResponse({'message': 'Data updated'}, status=200)

    elif request.method == 'DELETE':
        data_id = request.GET.get('data_id')
        if not data_id:
            return JsonResponse({'error': 'Data ID required'}, status=400)

        try:
            result = data_collection.delete_one({'_id': data_id, 'user_id': user['_id']})
            if result.deleted_count == 0:
                return JsonResponse({'error': 'Data not found or unauthorized'}, status=404)
        except Exception as e:
            logger.error(f"Failed to delete data: {str(e)}")
            return JsonResponse({'error': 'Failed to delete data'}, status=500)

        log_audit('data_delete', user['_id'], dict(request.GET))
        return JsonResponse({'message': 'Data deleted'}, status=200)

@csrf_exempt
def get_audit_logs(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    filters = dict(request.GET)
    query = {}
    if 'user_id' in filters:
        query['user_id'] = filters['user_id']
    if 'action' in filters:
        query['action'] = filters['action']

    try:
        logs = list(audit_collection.find(query, {'_id': 0}))
    except Exception as e:
        logger.error(f"Failed to retrieve audit logs: {str(e)}")
        return JsonResponse({'error': 'Failed to retrieve audit logs'}, status=500)
    return JsonResponse({'logs': logs}, status=200)