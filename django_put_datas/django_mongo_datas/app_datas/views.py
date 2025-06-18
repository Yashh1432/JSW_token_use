from pymongo import MongoClient
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from cryptography.fernet import Fernet
import uuid
import json
from datetime import datetime
from django.conf import settings
import base64

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['data_db']
data_collection = db['data_collection']

# Encryption setup
try:
    if not settings.ENCRYPTION_KEY:
        raise ValueError("ENCRYPTION_KEY is not set in settings")
    fernet = Fernet(settings.ENCRYPTION_KEY.encode())
except Exception as e:
    raise ValueError(f"Invalid ENCRYPTION_KEY: {str(e)}. Ensure it is a 32-byte URL-safe base64-encoded string.")

# Fields to encrypt
ENCRYPTED_FIELDS = ['name', 'email']

@csrf_exempt
def insert_data(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        # Generate UUID
        data['uuid'] = str(uuid.uuid4())
        data['created_at'] = datetime.utcnow()

        # Encrypt sensitive fields
        for field in ENCRYPTED_FIELDS:
            if field in data and data[field]:
                try:
                    data[field] = base64.b64encode(
                        fernet.encrypt(data[field].encode())
                    ).decode()
                except:
                    return JsonResponse({'error': f'Encryption failed for {field}'}, status=400)

        # Insert into MongoDB
        try:
            data_collection.insert_one(data)
        except Exception as e:
            return JsonResponse({'error': f'MongoDB insertion failed: {str(e)}'}, status=500)

        return JsonResponse({'message': 'Data inserted', 'uuid': data['uuid']}, status=201)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def fetch_data(request):
    if request.method == 'GET':
        uuid_param = request.GET.get('uuid')
        if not uuid_param:
            # Fetch all data
            try:
                records = list(data_collection.find({}, {'_id': 0}))
            except Exception as e:
                return JsonResponse({'error': f'MongoDB fetch failed: {str(e)}'}, status=500)

            # Decrypt sensitive fields
            for record in records:
                for field in ENCRYPTED_FIELDS:
                    if field in record and record[field]:
                        try:
                            record[field] = fernet.decrypt(
                                base64.b64decode(record[field])
                            ).decode()
                        except:
                            record[field] = 'Decryption failed'
            return JsonResponse({'data': records}, status=200)

        # Fetch by UUID
        try:
            record = data_collection.find_one({'uuid': uuid_param}, {'_id': 0})
        except Exception as e:
            return JsonResponse({'error': f'MongoDB fetch failed: {str(e)}'}, status=500)

        if not record:
            return JsonResponse({'error': 'Data not found'}, status=404)

        # Decrypt sensitive fields
        for field in ENCRYPTED_FIELDS:
            if field in record and record[field]:
                try:
                    record[field] = fernet.decrypt(
                        base64.b64decode(record[field])
                    ).decode()
                except:
                    record[field] = 'Decryption failed'

        return JsonResponse({'data': record}, status=200)
    return JsonResponse({'error': 'Method not allowed'}, status=405)