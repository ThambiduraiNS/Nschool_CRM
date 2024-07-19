from django.urls import path
from .views import *

urlpatterns = [
    path('admin/login/', admin_login, name='admin_login'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('user_module/', user_module_view, name='user-module'),
    path('manage_user/', manage_user_view, name='manage-user'),
    
    path('logout/', logout, name='logout'),
    
    path('api/login/', user_login, name='login'),
    path('api/logout/', user_logout, name='logout'),
]