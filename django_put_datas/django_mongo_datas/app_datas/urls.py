from django.urls import path
from . import views

urlpatterns = [
    path('insert/', views.insert_data, name='insert_data'),
    path('fetch/', views.fetch_data, name='fetch_data'),
    path('update/patch/', views.update_data_patch, name='update_data_patch'),
    path('update/put/', views.update_data_put, name='update_data_put'),
]