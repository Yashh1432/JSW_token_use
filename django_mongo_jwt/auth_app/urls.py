# urls.py (unchanged from previous)
from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('audit/', views.get_audit_logs, name='audit'),
    path('data/', views.data_operations, name='data_operations'),
]