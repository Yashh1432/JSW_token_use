from pymongo import MongoClient
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['jwt_auth_db']
users_collection = db['users']
audit_collection = db['audit']

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
from django.conf import settings

# Helper function to log audit
def log_audit(action, username, email, query_params):
    audit_collection.insert_one({
        'action': action,
        'username': username,
        'email': email,
        'timestamp': datetime.utcnow(),
        'query_params': query_params
    })
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
        
        log_audit('register_get', user.get('username', ''), email, dict(request.GET))
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
            user = {
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

        log_audit(action, username, email, dict(request.GET))
        return JsonResponse({'message': f'User {request.method.lower()}ed successfully'}, status=200)

    elif request.method == 'DELETE':
        if not email:
            return JsonResponse({'error': 'Email required'}, status=400)
        existing_user = users_collection.find_one({'email': email})
        if not existing_user:
            return JsonResponse({'error': 'User not found'}, status=404)
        users_collection.delete_one({'email': email})
        
        log_audit('register_delete', existing_user.get('username', ''), email, dict(request.GET))
        return JsonResponse({'message': 'User deleted'}, status=200)

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
            log_audit('login_failed', user.get('username', '') if user else '', email, dict(request.GET))
            return JsonResponse({'error': 'Invalid credentials'}, status=401)

        token = jwt.encode({
            'sub': email,
            'exp': datetime.utcnow() + timedelta(seconds=settings.JWT_EXPIRATION_DELTA)
        }, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

        log_audit('login', user.get('username', ''), email, dict(request.GET))
        return JsonResponse({'token': token}, status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def logout(request):
    if request.method == 'POST':
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            log_audit('logout_failed', '', '', dict(request.GET))
            return JsonResponse({'error': 'Invalid token'}, status=401)

        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            email = payload['sub']
            user = users_collection.find_one({'email': email})

            log_audit('logout', user.get('username', '') if user else '', email, dict(request.GET))
            return JsonResponse({'message': 'Logged out'}, status=200)
        except jwt.JWTError:
            log_audit('logout_failed', '', '', dict(request.GET))
            return JsonResponse({'error': 'Invalid token'}, status=401)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def get_audit_logs(request):
    if request.method == 'GET':
        filters = dict(request.GET)
        query = {}
        if 'username' in filters:
            query['username'] = filters['username'][0]
        if 'email' in filters:
            query['email'] = filters['email'][0]
        if 'action' in filters:
            query['action'] = filters['action'][0]

        logs = list(audit_collection.find(query, {'_id': 0}))
        return JsonResponse({'logs': logs}, status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)