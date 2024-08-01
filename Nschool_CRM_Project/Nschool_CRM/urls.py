from django.urls import path
from .views import *

urlpatterns = [
    path('login/', admin_login, name='admin_login'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('user_module/', user_module_view, name='user-module'),
    path('manage_user/', manage_user_view, name='manage-user'),
    path('delete_user/<int:id>/', delete_user_view, name='delete-user'),
    path('update_user/<int:id>/', update_user_view, name='update-user'),
    path('delete_all_user/', delete_all_users_view, name='delete-all-user'),
    
    path('export_user_csv/', export_user_csv, name='export_user_csv'),
    path('export_user_excel/', export_user_excel, name='export_user_excel'),
    path('export_user_pdf/', export_user_pdf, name='export_user_pdf'),
    
    path("search/", SearchResultsView.as_view(), name="search_results"),
    
    path('logout/', logout, name='logout'),
    
    path('api/login/', user_login, name='login'),
    path('api/logout/', user_logout, name='api-logout'),
    path('api/newuser/', NewUserListCreateView.as_view(), name='newuser_list_create'),
    path('api/newuser/<int:pk>/', NewUserDetailView.as_view(), name='course_detail'),
    path('api/update_newuser/<int:pk>/', NewUserUpdateView.as_view(), name='course_update'),
    path('api/delete_newuser/<int:pk>/', NewUserDeleteView.as_view(), name='course_delete'),
]