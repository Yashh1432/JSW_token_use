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
fernet = Fernet(settings.ENCRYPTION_KEY.encode())

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
                data[field] = base64.b64encode(
                    fernet.encrypt(data[field].encode())
                ).decode()

        # Insert into MongoDB
        data_collection.insert_one(data)
        return JsonResponse({'message': 'Data inserted', 'uuid': data['uuid']}, status=201)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def fetch_data(request):
    if request.method == 'GET':
        uuid_param = request.GET.get('uuid')
        if not uuid_param:
            # Fetch all data if no UUID provided
            records = list(data_collection.find({}, {'_id': 0}))
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
        record = data_collection.find_one({'uuid': uuid_param}, {'_id': 0})
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