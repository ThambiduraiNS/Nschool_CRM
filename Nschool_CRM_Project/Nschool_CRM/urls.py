from django.urls import path
from . import views
urlpatterns = [
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('user_module/', views.user_module_view, name='user-module'),
]