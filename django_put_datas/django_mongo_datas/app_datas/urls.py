from django.urls import path
from . import views

urlpatterns = [
    path('insert/', views.insert_data, name='insert_data'),
    path('fetch/', views.fetch_data, name='fetch_data'),
]