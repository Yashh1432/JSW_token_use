from django.urls import path, include

urlpatterns = [
    path('api/data/', include('data_app.urls')),
]