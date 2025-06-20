from django.urls import path, include

urlpatterns = [
    path('api/', include('food_app.urls')),
]