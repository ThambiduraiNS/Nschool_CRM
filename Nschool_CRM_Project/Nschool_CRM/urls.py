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
    
    # search Attributes details
    path('search_attribute/', SearchAttributeResultsView.as_view(), name='search_attribute'),
    
    # search Attributes details
    path('search_enquiry/', SearchEnquiryResultsView.as_view(), name='search_enquiry'),
    
    path('logout/', logout, name='logout'),
    
    
    # course module
    path('add_course/', add_course_view, name='add-course'),
    path('manage_course/', manage_course_view, name='manage-course'),
    path('delete_course/<int:id>/', delete_course_view, name='delete-course'),
    path('update_course/<int:id>/', update_course_view, name='update-course'),
    path('delete_all_course/', delete_all_course_view, name='delete-all-course'),
    
    # Attributes module
    path('add_attribute/', add_attribute_view, name='add_attribute'),
    path('manage_attribute/', manage_attribute_view, name='manage_attribute'),
    path('delete_attribute/<int:id>/', delete_attribute_view, name='delete_attribute'),
    path('update_attribute/<int:id>/', update_attribute_view, name='update_attribute'),
    path('delete_all_attributes/', delete_all_attributes_view, name='delete_all_attributes'),
    
    # enquiry module
    path('enquiry/', enquiry_view, name='enquiry'),
    path('manage_enquiry/', manage_enquiry_view, name='manage_enquiry'),
    path('update_enquiry/<int:id>/', update_enquiry_view, name='update_enquiry'),
    path('delete_enquiry/<int:id>/', delete_enquiry_view, name='delete_enquiry'),
    path('delete_all_enquiry/', delete_all_enquiry_view, name='delete_all_enquiry'),
    
    path('delete_notes/<int:id>/', delete_notes_view, name='delete_notes_view'),
    path('update_notes/<int:id>/', update_notes_view, name='delete_notes_view'),
    
    # enrollment module
    path('enrollment/', new_enrollment_view, name='enrollment'),
    path('manage_enrollment/', manage_enrollment_view, name='manage_enrollment'),
    path('update_enrollment/<int:id>/', update_enrollment_view, name='update_enrollment'),
    path('delete_enrollment/<int:id>/', delete_enrollment_view, name='delete_enrollment'),
    path('delete_all_enrollment/', delete_all_enrollment_view, name='delete_all_enrollment'),
    path('get-enquiry-details/', get_enquiry_details, name='get_enquiry_details'),
    
    # file formate for attributes
    path('export_attributes_csv/', export_attributes_csv, name='export_attributes_csv'),
    path('export_attributes_excel/', export_attributes_excel, name='export_attributes_excel'),
    path('export_attributes_pdf/', export_attributes_pdf, name='export_attributes_pdf'),
    
    # file formate for attributes
    path('export_enquiry_csv/', export_enquiry_csv, name='export_enquiry_csv'),
    path('export_enquiry_excel/', export_enquiry_excel, name='export_enquiry_excel'),
    path('export_enquiry_pdf/', export_enquiry_pdf, name='export_enquiry_pdf'),
    
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
    
    # API for Enquiry Mode module
    path('api/enquiry_mode/', EnquiryModeListCreateView.as_view(), name='enquiry_mode_list_create'),
    path('api/enquiry_mode/<int:pk>/', EnquiryModeDetailView.as_view(), name='enquiry_mode_detail'),
    path('api/update_enquiry_mode/<int:pk>/', EnquiryModeUpdateView.as_view(), name='enquiry_mode_update'),
    path('api/delete_enquiry_mode/<int:pk>/', EnquiryModeDeleteView.as_view(), name='enquiry_mode_delete'),
    
    path('api/notes/<int:pk>/', NotesDetailView.as_view(), name='notes'),
    path('api/update_notes/<int:pk>/', NotesUpdateView.as_view(), name='notes_update'),
    path('api/delete_notes/<int:pk>/', NotesDeleteView.as_view(), name='notes_delete'),
    
    # API for enquiry module
    path('api/enquiry/', EnquiryListCreateView.as_view(), name='enquiry_list_create'),
    path('api/enquiry/<int:pk>/', EnquiryDetailView.as_view(), name='enquiry_detail'),
    path('api/update_enquiry/<int:pk>/', EnquiryUpdateView.as_view(), name='enquirye_update'),
    path('api/delete_enquiry/<int:pk>/', EnquiryDeleteView.as_view(), name='enquiry_delete'),
    
    # API for Enrollment module
    path('api/enrollment/', EnrollmentListCreateView.as_view(), name='enrollment_list_create'),
    path('api/enrollment/<int:pk>/', EnrollmentDetailView.as_view(), name='enrollment_detail'),
    path('api/update_enrollment/<int:pk>/', EnrollmentUpdateView.as_view(), name='enrollment_update'),
    path('api/delete_enrollment/<int:pk>/', EnrollmentDeleteView.as_view(), name='enrollment_delete'),
    
    
]