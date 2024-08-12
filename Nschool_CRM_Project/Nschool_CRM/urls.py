from django.urls import path
from .views import *

urlpatterns = [
    # user module
    path('login/', admin_login, name='admin_login'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('user_module/', user_module_insert_view, name='user-module'),
    path('manage_user/', manage_user_view, name='manage-user'),
    path('delete_user/<int:id>/', delete_user_view, name='delete-user'),
    path('update_user/<int:id>/', update_user_view, name='update-user'),
    path('delete_all_user/', delete_all_users_view, name='delete-all-user'),
    
    # file formate for user
    path('export_user_csv/', export_user_csv, name='export_user_csv'),
    path('export_user_excel/', export_user_excel, name='export_user_excel'),
    path('export_user_pdf/', export_user_pdf, name='export_user_pdf'),
    
    # file formate for course
    path('export_course_csv/', export_course_csv, name='export_course_csv'),
    path('export_course_excel/', export_course_excel, name='export_course_excel'),
    path('export_course_pdf/', export_course_pdf, name='export_course_pdf'),
    
    # search user details
    path("search_user/", SearchResultsView.as_view(), name='search_results'),
    
    # search course details
    path('search_courses/', SearchCourseResultsView.as_view(), name='search_courses'),
    
    path('logout/', logout, name='logout'),
    
    
    # course module
    path('add_course/', add_course_view, name='add-course'),
    path('manage_course/', manage_course_view, name='manage-course'),
    path('delete_course/<int:id>/', delete_course_view, name='delete-course'),
    path('update_course/<int:id>/', update_course_view, name='update-course'),
    path('delete_all_course/', delete_all_course_view, name='delete-all-course'),
    
    # Enquiry module
    path('enquiry/', enquiry_view, name='enquiry'),
    
    # API for login and logout
    path('api/login/', user_login, name='login'),
    path('api/logout/', user_logout, name='api-logout'),
    
    # API for user module
    path('api/newuser/', NewUserListCreateView.as_view(), name='newuser_list_create'),
    path('api/newuser/<int:pk>/', NewUserDetailView.as_view(), name='course_detail'),
    path('api/update_newuser/<int:pk>/', NewUserUpdateView.as_view(), name='course_update'),
    path('api/delete_newuser/<int:pk>/', NewUserDeleteView.as_view(), name='course_delete'),
    
    # API for course module
    path('api/course/', CourseListCreateView.as_view(), name='course_list_create'),
    path('api/course/<int:pk>/', CourseDetailView.as_view(), name='course_detail'),
    path('api/update_course/<int:pk>/', CourseUpdateView.as_view(), name='course_update'),
    path('api/delete_course/<int:pk>/', CourseDeleteView.as_view(), name='course_delete'),
    
    # API for enquiry module
    path('api/enquiry/', EnquiryListCreateView.as_view(), name='enquiry_list_create'),
    path('api/enquiry/<int:pk>/', EnquiryDetailView.as_view(), name='enquiry_detail'),
    path('api/update_enquiry/<int:pk>/', EnquiryUpdateView.as_view(), name='enquirye_update'),
    path('api/delete_enquiry/<int:pk>/', EnquiryDeleteView.as_view(), name='enquiry_delete'),
]