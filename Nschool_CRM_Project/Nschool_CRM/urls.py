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
    
    # search enquiry details
    path('search_enquiry/', SearchEnquiryResultsView.as_view(), name='search_enquiry'),
    
    # search enrollment details
    path('search_enrollment/', SearchEnrollmentResultsView.as_view(), name='search_enrollment'),
    
    # search payment details
    path('search_payment/', SearchPaymentResultsView.as_view(), name='search_payment'),
    
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
    
    # payment module
    path('payment/', new_payment_view, name='payment'),
    path('manage_payment/', manage_payment_view, name='manage_payment'),
    path('delete_payment/<int:id>/', delete_payment_view, name='delete_payment'),
    path('update_payment/<int:id>/', update_payment_view, name='update_payment'),
    path('delete_all_payment/', delete_all_payment_view, name='delete_all_payment'),
    path('get-enrollment-details/', get_enrollment_details, name='get_enrollment_details'),
    
    
    path('new-payment/', new_payment_info_view, name='new_payment_info'),
    path('installment-payment/', installment_view, name='installment_payment'),
    path('single-payment/', single_payment_view, name='single_payment'),
    path('single-payment/<int:id>/', single_payment_update_view, name='single_payment'),
    path('installment-payment/<int:id>/', installment_update_view, name='installment_payment'),
    path('single-payment/<int:id>/', single_payment_view, name='single_payment'),
    path('manage-payments/', manage_payment_info_view, name='manage_payments'),
    
    # file formate for enrollment
    path('export_payment_csv/', export_payment_csv, name='export_payment_csv'),
    path('export_payment_excel/', export_payment_excel, name='export_payment_excel'),
    path('export_payment_pdf/', export_payment_pdf, name='export_payment_pdf'),
    
    # file formate for enrollment
    path('export_enrollment_csv/', export_enrollment_csv, name='export_enrollment_csv'),
    path('export_enrollment_excel/', export_enrollment_excel, name='export_enrollment_excel'),
    path('export_enrollment_pdf/', export_enrollment_pdf, name='export_enrollment_pdf'),
    
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
    
    # API for Payment module
    path('api/payment/', PaymentListCreateView.as_view(), name='payment_list_create'),
    path('api/payment/<int:pk>/', PaymentDetailView.as_view(), name='payment_detail'),
    path('api/update_payment/<int:pk>/', PaymentUpdateView.as_view(), name='payment_update'),
    path('api/delete_payment/<int:pk>/', PaymentDeleteView.as_view(), name='payment_delete'),
    
    # API for PaymentInfo module
    path('api/payment_info/', PaymentInfoListCreateView.as_view(), name='payment_info_list_create'),
    path('api/payment_info/<int:pk>/', PaymentInfoDetailView.as_view(), name='payment_info_detail'),
    path('api/update_payment_info/<int:pk>/', PaymentInfoUpdateView.as_view(), name='payment_info_update'),
    path('api/delete_payment_info/<int:pk>/', PaymentInfoDeleteView.as_view(), name='payment_info_delete'),
    
    # API for Installment module
    path('api/installment/', InstallmentListCreateView.as_view(), name='installment_list_create'),
    path('api/installment/<int:pk>/', InstallmentDetailView.as_view(), name='installment_detail'),
    path('api/update_installment/<int:pk>/', InstallmentUpdateView.as_view(), name='installment_update'),
    path('api/delete_installment/<int:pk>/', InstallmentDeleteView.as_view(), name='installment_delete'),
    
    # API for SinglePayment module
    path('api/single_payment/', SinglePaymentListCreateView.as_view(), name='single_payment_list_create'),
    path('api/single_payment/<int:pk>/', SinglePaymentDetailView.as_view(), name='single_payment_detail'),
    path('api/update_single_payment/<int:pk>/', SinglePaymentUpdateView.as_view(), name='single_payment_update'),
    path('api/delete_single_payment/<int:pk>/', SinglePaymentDeleteView.as_view(), name='single_payment_delete'),
]