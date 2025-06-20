from django.urls import path
from . import views

urlpatterns = [
    path('foods/', views.food_operations, name='food_operations'),
]