from pymongo import MongoClient
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime
import re

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['demo']
foods_collection = db['food_api']

@csrf_exempt
def food_operations(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    food_name = request.GET.get('name')

    try:
        if food_name:
            # Case-insensitive search using regex
            food = foods_collection.find_one({
                'name': {'$regex': '^' + re.escape(food_name) + '$', '$options': 'i'}
            })
            if not food:
                return JsonResponse({'error': f'Food item "{food_name}" not found'}, status=404)
            
            response = {
                'food_id': food['_id'],
                'name': food['name'],
                'description': food['description'],
                'price': food['price'],
                'created_at': food['created_at'].isoformat()
            }
            return JsonResponse({'food': response}, status=200)
        else:
            # Fetch all foods
            foods = list(foods_collection.find())
            response = [
                {
                    'food_id': food['_id'],
                    'name': food['name'],
                    'description': food['description'],
                    'price': food['price'],
                    'created_at': food['created_at'].isoformat()
                } for food in foods
            ]
            return JsonResponse({'foods': response}, status=200)

    except Exception as e:
        return JsonResponse({'error': 'Failed to retrieve food data'}, status=500)