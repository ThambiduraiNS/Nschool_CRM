from django.urls import path
from .views import *

urlpatterns = [
    path('admin/login/', admin_login, name='admin_login'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('user_module/', user_module_view, name='user-module'),
    path('manage_user/', manage_user_view, name='manage-user'),
    
    path('api/new_user/', UserListCreate.as_view(), name='user-list-create'),
    path('api/new_user/<int:pk>/', UserDetail.as_view(), name='user-detail'),
]