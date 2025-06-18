from django.urls import path, include

urlpatterns = [
    path('api/data/', include('app_datas.urls')),
]