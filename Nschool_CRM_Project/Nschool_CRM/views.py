
from io import BytesIO
import json, requests
from django.core.files.uploadedfile import InMemoryUploadedFile

from django.shortcuts import redirect, render
from django.contrib.auth import authenticate
from django.contrib.auth import authenticate, login , logout as auth_logout
from django.template import RequestContext
from yaml import Loader
from .models import NewUser, Course
from django.contrib.auth.decorators import login_required

from django.core.cache import cache
from django.core.paginator import Paginator

from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from .serializer import NewUserSerializer

from rest_framework.authtoken.models import Token
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect

from django.core.exceptions import ObjectDoesNotExist
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status

from .serializer import *

import csv
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from PIL import Image as PILImage
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

import openpyxl
from django.http import Http404
from openpyxl.drawing.image import Image as ExcelImage
from openpyxl.styles import Font, Alignment, Border, Side
from PIL import Image as PILImage
from io import BytesIO
import re
from . import renderers

from .utils import encrypt_password, decrypt_password
from django.views.generic import TemplateView, ListView
from django.db.models import Q

from django.contrib import messages

@csrf_protect
def admin_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        print(email, password)
        
        url = 'http://127.0.0.1:8000/api/login/'
        # data = {'username': username, 'password': password}
        data = {'username_or_email': email, 'password': password, 'username': username}
        csrf_token = request.COOKIES.get('csrftoken')
        
        try:
            headers = {
                'X-CSRFToken': csrf_token
            }
            response = requests.post(url, data=data, headers=headers)
            # response.raise_for_status()  # Raise an HTTPError for bad responses
            response_data = response.json()
    
        except requests.exceptions.RequestException as e:
            context = {
                'errors': f'Error occurred: {e}'
            }
            return render(request, 'admin_login.html', context)
        
        if response.status_code == 200:
            user = authenticate(request, email=email, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
            else:
                context = {'error': 'Invalid credentials'}
                return render(request, 'admin_login.html', context)
        else:
            context = {
                'error': response_data.get('user_error', response_data.get('pass_error', response_data.get('error', 'Invalid credentials')))
            }
            return render(request, 'admin_login.html', context)
    
    return render(request, 'admin_login.html')

def logout(request):
    token = Token.objects.get()
    api_url = 'http://127.0.0.1:8000/api/logout/'
    headers = {
        'Authorization': f'Token {token.key}'
    }
    
    try:
        response = requests.post(api_url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f'Error during API logout: {e}')
        return redirect('dashboard')  # Redirect to dashboard or show an error message

    # Remove the token locally after successful API logout
    token.delete()

    # Log out the user and clear the session
    auth_logout(request)
    request.session.flush()

    return redirect('admin_login')

def dashboard_view(request):
    datapoints = [
        { "x": 10, "y": 171 },
        { "x": 20, "y": 155},
        { "x": 30, "y": 150 },
        { "x": 40, "y": 165 },
        { "x": 50, "y": 195 },
        { "x": 60, "y": 168 },
        { "x": 70, "y": 128 },
        { "x": 80, "y": 134 },
        { "x": 90, "y": 114}
    ]
 
    datapoints2 = [
        { "x": 10, "y": 71 },
        { "x": 20, "y": 55},
        { "x": 30, "y": 50 },
        { "x": 40, "y": 65 },
        { "x": 50, "y": 95 },
        { "x": 60, "y": 68 },
        { "x": 70, "y": 28 },
        { "x": 80, "y": 34 },
        { "x": 90, "y": 14 }
    ]
    
    return render(request, 'dashboard.html',  { "datapoints" : json.dumps(datapoints), "datapoints2": json.dumps(datapoints2) })

def user_module_insert_view(request):
    if request.method == 'POST':
        # Extract data from the form
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        contact = request.POST.get("contact", "").strip()
        designation = request.POST.get("designation", "").strip()
        password = request.POST.get("password", "").strip()
        cpassword = request.POST.get("cpassword", "").strip()
        
        # Validate password
        if password != cpassword:
            context = {
                'error': 'Passwords do not match'
            }
            return render(request, 'new_user.html', context)


        # Encrypt the password
        encrypted_password = encrypt_password(password)
        
        
        # Prepare data for the API request
        user_data = {
            'username': username,
            'email': email.lower(),
            'contact': contact,
            'designation': designation,
            'password': encrypted_password.decode(),
            'enquiry': "Enquiry" in request.POST,
            'enrollment': "Enrollment" in request.POST,
            'attendance': "Attendance" in request.POST,
            'staff': "Staff" in request.POST,
            'placement': "Placement" in request.POST,
            'report': "Report" in request.POST,
        }

        # Get the token
        try:
            token = Token.objects.first()
        except Token.DoesNotExist:
            context = {
                'error': 'Authentication token not found'
            }
            return render(request, 'new_user.html', context)
        
        api_url = 'http://127.0.0.1:8000/api/newuser/'
        headers = {
            'Authorization': f'Token {token.key}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(api_url, json=user_data, headers=headers)
            response_data = response.json()
        except requests.exceptions.HTTPError as http_err:
            # Handle specific HTTP errors
            context = {
                'error': f'HTTP error occurred: {http_err}',
                'response_data': response.json()
            }
            return render(request, 'new_user.html', context)
        except requests.exceptions.RequestException as req_err:
            # Handle general request exceptions
            print(f'Error during API create New User: {req_err}')
            context = {
                'error': 'An error occurred while creating the new user.'
            }
            return render(request, 'new_user.html', context)        
        
        if response.status_code == 201:
            context =  {
                "message": "New User Created Successfully"
            }
            return render(request, 'new_user.html', context)
        else:
            error_messages = {
                'username': response_data.get('username', ''),
                'email': response_data.get('email', ''),
                'contact': response_data.get('contact', ''),
                'designation': response_data.get('designation', ''),
                'password': response_data.get('password', ''),
            }
            context = {
                'username': username,
                'email': email,
                'contact': contact,
                'designation': designation,
                'error_messages': error_messages,
            }
            return render(request, 'new_user.html', context)
        
    return render(request, 'new_user.html')

def manage_user_view(request):
    # Fetch the token
    try:
        token = Token.objects.first()  # Assuming you only have one token and it's safe to get the first one
    except Token.DoesNotExist:
        context = {
            'error': 'Authentication token not found'
        }
        return render(request, 'manage_user.html', context)
    
    api_url = 'http://127.0.0.1:8000/api/newuser/'
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        response_data = response.json()
        
        # Decrypt the passwords
        for user_data in response_data:
            encrypted_password = user_data.get('password')
            if encrypted_password:
                try:
                    user_data['password'] = decrypt_password(encrypted_password)
                except Exception as e:
                    user_data['password'] = 'Error decrypting password' 
        
    except requests.exceptions.RequestException as err:
        # Catch any request-related exceptions
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'manage_user.html', context)

    # Get the per_page value from the request, default to 10 if not provided
    per_page = request.GET.get('per_page', '10')

    # Apply pagination
    paginator = Paginator(response_data, per_page)  # Use response_data for pagination
    
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'per_page': per_page,
    }
    return render(request, 'manage_user.html', context)

def delete_user_view(request, id):
    user_id = NewUser.objects.get(id=id)
    
    print(user_id.pk)
    
    if not user_id:
        context = {'error': 'User ID not provided'}
        print("user id not provided")
        return render(request, 'manage_user.html', context)
    
    try:
        token = Token.objects.get()  # Get the first token for simplicity
        if not token:
            raise Token.DoesNotExist
    except Token.DoesNotExist:
        context = {'error': 'Authentication token not found'}
        return render(request, 'manage_user.html', context)
    
    api_url = f'http://127.0.0.1:8000/api/newuser/{user_id.pk}/'
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.delete(api_url, headers=headers)
        response.raise_for_status()
        print(response)
    except requests.exceptions.RequestException as err:
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'manage_user.html', context)
    
    if response.status_code == 204:
        return redirect('manage-user')
    
    else:
        response_data = response.json()
        context = {
            'detail': response_data.get('detail', 'An error occurred while deleting the user'),
        }
        return render(request, 'manage_user.html', context)

def delete_all_users_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_ids = data.get('user_ids', [])
            if user_ids:
                NewUser.objects.filter(id__in=user_ids).delete()
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'error': 'No users selected for deletion'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})
    

def update_user_view(request, id):
    try:
        user = NewUser.objects.get(id=id)
    except NewUser.DoesNotExist:
        context = {'error': 'User not found'}
        return render(request, 'manage_user.html', context)

    if request.method == 'POST':
        print("User before update:", user)
        
        try:
            token = Token.objects.first()  # Get the first token for simplicity
            if not token:
                raise Token.DoesNotExist
        except Token.DoesNotExist:
            context = {'error': 'Authentication token not found'}
            return render(request, 'manage_user.html', context)
        
        api_url = f'http://127.0.0.1:8000/api/update_newuser/{user.pk}/'
        headers = {
            'Authorization': f'Token {token.key}',
            'Content-Type': 'application/json'
        }
        
        user_data = {
            'username': request.POST.get('username', user.username),
            'email': request.POST.get('email', user.email),
            'contact': request.POST.get('contact', user.contact),
            'designation': request.POST.get('designation', user.designation),
            'enquiry': 'Enquiry' in request.POST,
            'enrollment': 'Enrollment' in request.POST,
            'attendance': 'Attendance' in request.POST,
            'staff': 'Staff' in request.POST,
            'placement': 'Placement' in request.POST,
            'report': 'Report' in request.POST,
        }
        
        print(user_data['enquiry'])
        
        print("User Data being sent:", user_data)

        try:
            response = requests.patch(api_url, data=json.dumps(user_data), headers=headers)
            print("API Response Status Code:", response.status_code)
            response.raise_for_status()
            response_data = response.json()
            print("API Response Data:", response_data)
        except requests.exceptions.RequestException as err:
            context = {
                'error': f'Request error occurred: {err}',
                'response_data': response.json() if response.content else {}
            }
            return render(request, 'manage_user.html', context)
        
        if response.status_code in [200, 204]:  # 204 No Content is also a valid response for updates
            print("Update successful")
            return redirect('manage-user')
        else:
            context = {
                'error': 'Failed to update user information',
                'username': response_data.get('username', ''),
                'email': response_data.get('email', ''),
                'contact': response_data.get('contact', ''),
                'designation': response_data.get('designation', ''),
            }
            return render(request, 'update_user.html', context)
        
    return render(request, 'update_user.html', {"user": user})
    
# create APIS

# user login api

import logging

logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request):
    serializer = LoginSerializer(data=request.data)
    
    print("serializer : ", serializer)

    if serializer.is_valid():
        username_or_email = serializer.validated_data['username_or_email']
        password = serializer.validated_data['password']

        print("email : ", username_or_email)
        print("password : ", password)

        user = authenticate(email=username_or_email, password=password)
        
        print(user)
        
        print(" Login user : ", user)
        
        if user:
            if not isinstance(user, (NewUser)):
                print("not a isinstance")
                return Response({'error': 'Invalid user type'}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                token, created = Token.objects.get_or_create(user=user)
                print("Token : ", token)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({'token': token.key}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# user logout api view
@api_view(["POST",])
@permission_classes([IsAuthenticated])
def user_logout(request):
    if request.method == "POST":
        request.user.auth_token.delete()
        return Response({"Message": "You are logged out"}, status=status.HTTP_200_OK)

# New user APi view

class NewUserListCreateView(generics.ListCreateAPIView):
    queryset = NewUser.objects.all().order_by('-id')
    serializer_class = NewUserSerializer
    permission_classes = [IsAuthenticated]
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({'Message': 'No users found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class NewUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = NewUser.objects.all()
    serializer_class = NewUserSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

class NewUserUpdateView(generics.RetrieveUpdateAPIView):
    queryset = NewUser.objects.all()
    serializer_class = NewUserUpdateSerializer
    permission_classes = [IsAuthenticated]
    partial = True
    
    
class NewUserDeleteView(generics.DestroyAPIView):
    queryset = NewUser.objects.all()
    serializer_class = NewUserSerializer
    permission_classes = [IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({'Message': 'Successfully deleted'})

# New Course APi view

class CourseListCreateView(generics.ListCreateAPIView):
    queryset = Course.objects.all().order_by('-id')
    serializer_class = CourseSerializer
    permission_classes = [IsAuthenticated]
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({'Message': 'No users found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class CourseDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

class CourseUpdateView(generics.RetrieveUpdateAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    permission_classes = [IsAuthenticated]
    partial = True
    
    
class CourseDeleteView(generics.DestroyAPIView):
    queryset = Course.objects.all()
    serializer_class = CourseSerializer
    permission_classes = [IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({'Message': 'Successfully deleted'})

# New Enquiry Mode APi view

class EnquiryModeListCreateView(generics.ListCreateAPIView):
    queryset = Enquiry_Mode.objects.all().order_by('-id')
    serializer_class = EnquiryModeSerializer
    permission_classes = [IsAuthenticated]
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({'Message': 'No users found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class EnquiryModeDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Enquiry_Mode.objects.all()
    serializer_class = EnquiryModeSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

class EnquiryModeUpdateView(generics.RetrieveUpdateAPIView):
    queryset = Enquiry_Mode.objects.all()
    serializer_class = EnquiryModeSerializer
    permission_classes = [IsAuthenticated]
    partial = True
    
    
class EnquiryModeDeleteView(generics.DestroyAPIView):
    queryset = Enquiry_Mode.objects.all()
    serializer_class = EnquiryModeSerializer
    permission_classes = [IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({'Message': 'Successfully deleted'})

# New Enquiry APi view

class EnquiryListCreateView(generics.ListCreateAPIView):
    queryset = Enquiry.objects.all().order_by('-id')
    serializer_class = EnquirySerializer
    permission_classes = [IsAuthenticated]
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if not queryset.exists():
            return Response({'Message': 'No users found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class EnquiryDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Enquiry.objects.all()
    serializer_class = EnquirySerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'

class EnquiryUpdateView(generics.RetrieveUpdateAPIView):
    queryset = Enquiry.objects.all()
    serializer_class = EnquirySerializer
    permission_classes = [IsAuthenticated]
    partial = True    
    
class EnquiryDeleteView(generics.DestroyAPIView):
    queryset = Enquiry.objects.all()
    serializer_class = EnquirySerializer
    permission_classes = [IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({'Message': 'Successfully deleted'})

# Api for notes
class NotesDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Notes.objects.all()
    serializer_class = NotesSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'pk'
    
class NotesUpdateView(generics.RetrieveUpdateAPIView):
    queryset = Notes.objects.all()
    serializer_class = NotesSerializer
    permission_classes = [IsAuthenticated]
    partial = True
    
class NotesDeleteView(generics.DestroyAPIView):
    queryset = Notes.objects.all()
    serializer_class = NotesSerializer
    permission_classes = [IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({'Message': 'Successfully deleted'})


@csrf_exempt
def export_user_csv(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')  # Get the ids from AJAX request

        # Create the HttpResponse object with the appropriate CSV header
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="course_list_csv.csv"'

        writer = csv.writer(response)

        # Write the header row
        writer.writerow(['Name', 'Email', 'Contact', 'Designation', 'Permission'])

        # Fetch selected courses based on IDs
        selected_courses = NewUser.objects.filter(id__in=ids)

        for user in selected_courses:
            # Remove country code from contact number
            contact_number = str(user.contact)
            # contact_number = re.sub(r'^\+\d{1,2}', '', contact_number)
            
            permission = []
                
            if user.enquiry == True:
                permission.append('Enquiry')
            
            if user.enrollment == True:
                permission.append('Enrollment')
            
            if user.attendance == True:
                permission.append('Attendance')
                
            if user.placement == True:
                permission.append('Permission')
            
            if user.staff == True:
                permission.append('Staff')
            
            if user.report == True:
                permission.append('Report')
                    
            # Write the data row
            writer.writerow([user.username, user.email, contact_number, user.designation, ', '.join(permission)])

        return response

    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX



from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def export_user_excel(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')  # Get the ids from AJAX request

        # Fetch selected courses based on IDs
        selected_courses = NewUser.objects.filter(id__in=ids)
        
        if not selected_courses:
            return JsonResponse({'error': 'No users available.'}, status=404)

        # Create an Excel workbook
        wb = openpyxl.Workbook()
        ws = wb.active

        # Define header row with font style and alignment
        header_row = ['Name', 'Email', 'Contact', 'Designation', 'Permission']
        ws.append(header_row)

        for idx, user in enumerate(selected_courses, start=2):
                
            permission = []
                
            if user.enquiry == True:
                permission.append('Enquiry')
            
            if user.enrollment == True:
                permission.append('Enrollment')
            
            if user.attendance == True:
                permission.append('Attendance')
                
            if user.placement == True:
                permission.append('Permission')
            
            if user.staff == True:
                permission.append('Staff')
            
            if user.report == True:
                permission.append('Report')
            
            ws.append([user.username, user.email, user.contact, user.designation, ', '.join(permission)])

        # Create an in-memory file-like object to save the workbook
        output = BytesIO()
        wb.save(output)
        output.seek(0)

        # Create the HTTP response with Excel content type and attachment header
        response = HttpResponse(output, content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="generated_excel.xlsx"'
        
        return response

    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX

from django.http import HttpResponse
from xhtml2pdf import pisa
from django.views.decorators.http import require_POST

@csrf_protect
@require_POST
def export_user_pdf(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')
        selected_users = NewUser.objects.filter(id__in=ids)
        
        if not selected_users:
            return JsonResponse({'error': 'No users available.'}, status=404)
        
        content_list = []
        for user in selected_users:
            # contact_number = re.sub(r'^\+\d{1,2}', '', contact_number)
                
            permission = []
                
            if user.enquiry == True:
                permission.append('Enquiry')
            
            if user.enrollment == True:
                permission.append('Enrollment')
            
            if user.attendance == True:
                permission.append('Attendance')
                
            if user.placement == True:
                permission.append('Permission')
            
            if user.staff == True:
                permission.append('Staff')
            
            if user.report == True:
                permission.append('Report')
                
            content_list.append({
                'username': user.username, 
                'email': user.email,
                'contact': user.contact,
                'designation': user.designation,
                'permission': ', '.join(permission),
            })
        
        content = {'user_list': content_list}
        return renderers.render_to_pdf('user_data_list.html', content)
    
    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX


class SearchResultsView(ListView):
    model = NewUser
    template_name = 'search_result.html'

    def get_queryset(self):
        query = self.request.GET.get("q")
        query_filter = Q()

        if query:
            query_lower = query.lower()
            
            boolean_fields = {
                'enquiry': 'enquiry',
                'enrollment': 'enrollment',
                'attendance': 'attendance',
                'staff': 'staff',
                'placement': 'placement',
                'report': 'report'
            }
            
            match_found = False
            for keyword, field in boolean_fields.items():
                if query_lower in keyword:
                    query_filter |= Q(**{f"{field}": True})
                    match_found = True
                    break

            if not match_found:
                # Search across CharField, EmailField, and PhoneNumberField
                fields = [f.name for f in NewUser._meta.fields if isinstance(f, (models.CharField, models.EmailField))]
                for field in fields:
                    query_filter |= Q(**{f"{field}__icontains": query})
        else:
            query_filter = Q(pk__isnull=True)

        object_list = NewUser.objects.filter(query_filter)
        return object_list


# course module

def add_course_view(request):
    if request.method == 'POST':
        # Extract data from the form
        course_name = request.POST.get("course", "").strip()
        
        # Prepare data for the API request
        user_data = {
            'course_name': course_name.lower(),
        }

        # Get the token
        try:
            token = Token.objects.first()
        except Token.DoesNotExist:
            context = {
                'error': 'Authentication token not found'
            }
            return render(request, 'add_course.html', context)
        
        api_url = 'http://127.0.0.1:8000/api/course/'
        headers = {
            'Authorization': f'Token {token.key}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(api_url, json=user_data, headers=headers)
            response_data = response.json()
            
            print(response_data)
            
        except requests.exceptions.HTTPError as http_err:
            # Handle specific HTTP errors
            context = {
                'error': f'HTTP error occurred: {http_err}',
                'response_data': response.json()
            }
            return render(request, 'add_course.html', context)
        except requests.exceptions.RequestException as req_err:
            # Handle general request exceptions
            print(f'Error during API create Course: {req_err}')
            context = {
                'error': 'An error occurred while creating course.'
            }
            return render(request, 'add_course.html', context)        
        
        if response.status_code == 201:
            context =  {
                "message": "New Course Created Successfully"
            }
            return render(request, 'add_course.html', context)
        else:
            context = {
                'course': response_data.get('course_name', ''),
            }
            return render(request, 'add_course.html', context)
        
    return render(request, 'add_course.html')

def manage_course_view(request):
    # Fetch the token
    try:
        token = Token.objects.first()  # Assuming you only have one token and it's safe to get the first one
    except Token.DoesNotExist:
        context = {
            'error': 'Authentication token not found'
        }
        return render(request, 'manage_user.html', context)
    
    api_url = 'http://127.0.0.1:8000/api/course/'
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        response_data = response.json()
        
    except requests.exceptions.RequestException as err:
        # Catch any request-related exceptions
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'manage_course.html', context)

    # Get the per_page value from the request, default to 10 if not provided
    per_page = request.GET.get('per_page', '10')

    # Apply pagination
    paginator = Paginator(response_data, per_page)  # Use response_data for pagination
    
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'per_page': per_page,
    }
    return render(request, 'manage_course.html', context)

def delete_course_view(request, id):
    user_id = Course.objects.get(id=id)
    
    print(user_id.pk)
    
    if not user_id:
        context = {'error': 'User ID not provided'}
        print("user id not provided")
        return render(request, 'manage_course.html', context)
    
    try:
        token = Token.objects.get()  # Get the first token for simplicity
        if not token:
            raise Token.DoesNotExist
    except Token.DoesNotExist:
        context = {'error': 'Authentication token not found'}
        return render(request, 'manage_course.html', context)
    
    api_url = f'http://127.0.0.1:8000/api/course/{user_id.pk}/'
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.delete(api_url, headers=headers)
        response.raise_for_status()

    except requests.exceptions.RequestException as err:
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'manage_course.html', context)
    
    if response.status_code == 204:
        return redirect('manage-course')
    
    else:
        response_data = response.json()
        context = {
            'detail': response_data.get('detail', 'An error occurred while deleting the user'),
        }
        return render(request, 'manage_course.html', context)
    
def delete_all_course_view(request):
    if request.method == 'POST':
        print("Welcome")
        try:
            data = json.loads(request.body)
            
            print("Data : ", data)
            
            user_ids = data.get('user_ids', [])
            
            if user_ids:
                Course.objects.filter(id__in=user_ids).delete()
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'error': 'No users selected for deletion'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

def update_course_view(request, id):
    try:
        user = Course.objects.get(id=id)
    except Course.DoesNotExist:
        context = {'error': 'Course not found'}
        return render(request, 'manage_course.html', context)

    if request.method == 'POST':
        
        try:
            token = Token.objects.first()  # Get the first token for simplicity
            if not token:
                raise Token.DoesNotExist
        except Token.DoesNotExist:
            context = {'error': 'Authentication token not found'}
            return render(request, 'manage_user.html', context)
        
        api_url = f'http://127.0.0.1:8000/api/update_course/{user.pk}/'
        headers = {
            'Authorization': f'Token {token.key}',
            'Content-Type': 'application/json'
        }
        
        user_data = {
            'course_name': request.POST.get('course', user.course_name),
        }

        try:
            response = requests.patch(api_url, data=json.dumps(user_data), headers=headers)
            print("API Response Status Code:", response.status_code)
            response.raise_for_status()
            response_data = response.json()
            print("API Response Data:", response_data)
        except requests.exceptions.RequestException as err:
            context = {
                'error': f'Request error occurred: {err}',
                'response_data': response.json() if response.content else {}
            }
            return render(request, 'manage_course.html', context)
        
        if response.status_code in [200, 204]:  # 204 No Content is also a valid response for updates
            print("Update successful")
            return redirect('manage-course')
        else:
            context = {
                'error': 'Failed to update user information',
                'course_name': response_data.get('course_name', ''),
            }
            return render(request, 'update_course.html', context)
        
    return render(request, 'update_course.html', {"course": user})

# csv file formate for course
@csrf_exempt
def export_course_csv(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')  # Get the ids from AJAX request

        # Create the HttpResponse object with the appropriate CSV header
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="course_list_csv.csv"'

        writer = csv.writer(response)

        # Write the header row
        writer.writerow(['Course Name'])

        # Fetch selected courses based on IDs
        selected_courses = Course.objects.filter(id__in=ids)

        for user in selected_courses:        
            # Write the data row
            writer.writerow([user.course_name])

        return response

    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX

# Excel file format for course
@csrf_exempt
def export_course_excel(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')  # Get the ids from AJAX request

        # Fetch selected courses based on IDs
        selected_courses = Course.objects.filter(id__in=ids)

        # Create an Excel workbook
        wb = openpyxl.Workbook()
        ws = wb.active

        # Define header row with font style and alignment
        header_row = ['Course Name']
        ws.append(header_row)

        for idx, user in enumerate(selected_courses, start=2):
            ws.append([user.course_name])

        # Create an in-memory file-like object to save the workbook
        output = BytesIO()
        wb.save(output)
        output.seek(0)

        # Create the HTTP response with Excel content type and attachment header
        response = HttpResponse(output, content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="generated_excel.xlsx"'
        
        return response

    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX

@csrf_protect
@require_POST
def export_course_pdf(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')
        selected_users = Course.objects.filter(id__in=ids)
        
        if not selected_users:
            return JsonResponse({'error': 'No users available.'}, status=404)
        
        content_list = []
        for user in selected_users:    
            content_list.append({
                'course_name': user.course_name, 
            })
        
        content = {'course_list': content_list}
        return renderers.render_to_pdf('course_data_list.html', content)
    
    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX

class SearchCourseResultsView(ListView):
    model = Course
    template_name = 'search_course_result.html'

    def get_queryset(self):
        query = self.request.GET.get("q")
        
        object_list = Course.objects.filter(
            Q(course_name__icontains = query)
        )
        
        return object_list

# def enquiry_view(request):
    
#     # Extract data from the form
#     # last_enquiry_no = Enquiry.objects.latest('enquiry_date').enquiry_no
    
#     # Get the last enquiry_no
#     try:
#         last_enquiry_no = Enquiry.objects.latest('id').enquiry_no
#     except Enquiry.DoesNotExist:
#         last_enquiry_no = "EWT-0000" 

#     print(last_enquiry_no)
#     # Extract the numeric part and increment it
#     numeric_part = int(last_enquiry_no.split('-')[1])
#     incremented_numeric_part = numeric_part + 1

#     print(incremented_numeric_part)

#     # Format the incremented value with leading zeros
#     new_enquiry_no = f"EWT-{incremented_numeric_part:04d}"
    
#     print(new_enquiry_no)
    
#     if request.method == 'POST':
#         enquiry_data = {
#             'enquiry_date': request.POST.get('enquiry_date', '').strip(),
#             'enquiry_no': request.POST.get('enquiry_number', '').strip(),
#             'enquiry_no': new_enquiry_no,
#             'name': request.POST.get('student_name', '').strip(),
#             'contact_no': request.POST.get('contact', '').strip(),
#             'email_id': request.POST.get('email', '').strip(),
#             'date_of_birth': request.POST.get('dob', '').strip(),
#             'fathers_name': request.POST.get('father_name', '').strip(),
#             'fathers_contact_no': request.POST.get('father_contact', '').strip(),
#             'fathers_occupation': request.POST.get('fathers_occupation', '').strip(),
#             'address': request.POST.get('address', '').strip(),
#             'status': request.POST.get('status', '').strip(),
#             'course_name': request.POST.get('course_name', '').strip(),
#             'inplant_technology': request.POST.get('technology', '').strip(),
#             'inplant_no_of_days': request.POST.get('inplant_no_of_days', '').strip(),
#             'inplant_no_of_students': request.POST.get('inplant_no_of_students', '').strip(),
#             'internship_technology': request.POST.get('technology', '').strip(),
#             'internship_no_of_days': request.POST.get('internship_no_of_days', '').strip(),
#             'next_follow_up_date': request.POST.get('next_follow_up_date', '').strip(),
#             'degree': request.POST.get('degree', '').strip(),
#             'college': request.POST.get('college', '').strip(),
#             'grade_persentage': request.POST.get('grade_persentage', '').strip(),
#             'year_of_graduation': request.POST.get('year_of_graduation', '').strip(),
#             'mode_of_enquiry': request.POST.get('mode_of_enquiry', '').strip(),
#             'reference_name': request.POST.get('reference_name', '').strip(),
#             'reference_contact_no': request.POST.get('reference_contact', '').strip(),
#             'other_enquiry_details': request.POST.get('other_enquiry_details', '').strip(),
#         }
        
#         print(enquiry_data['enquiry_no'])
        
#         # Get the token
#         try:
#             token = Token.objects.get(user=request.user)
#         except Token.DoesNotExist:
#             context = {
#                 'error': 'Authentication token not found'
#             }
#             return render(request, 'new_enquiry.html', context)
        
#         api_url = 'http://127.0.0.1:8000/api/enquiry/'  # Adjust the URL as needed
#         headers = {
#             'Authorization': f'Token {token.key}',
#             'Content-Type': 'application/json'
#         }

#         try:
#             response = requests.post(api_url, json=enquiry_data, headers=headers)
#             response_data = response.json()
            
#             print(response_data.get('name'))
            
#         except requests.exceptions.HTTPError as http_err:
#             # Handle specific HTTP errors
#             context = {
#                 'error': f'HTTP error occurred: {http_err}',
#                 'response_data': response.json()
#             }
#             return render(request, 'new_enquiry.html', context)
#         except requests.exceptions.RequestException as req_err:
#             # Handle general request exceptions
#             print(f'Error during API create Enquiry: {req_err}')
#             context = {
#                 'error': 'An error occurred while creating the enquiry.'
#             }
#             return render(request, 'new_enquiry.html', context)        
        
#         if response.status_code == 201:
#             messages.success(request, 'New Enquiry Created Successfully')
#             return redirect('enquiry')
#         else:
#             # Fetch available courses and mode of enquiry choices for the form
#             courses = Course.objects.all()
#             mode_of_enquiry_choices = Enquiry_Mode.objects.all()
#             context = {
#                 'error': response_data.get('error', 'An error occurred during enquiry creation.'),
#                 'enquiry_date': response_data.get('enquiry_date', ''),
#                 'enquiry_no': response_data.get('enquiry_no', ''),
#                 'name': response_data.get('name', ''),
#                 'contact_no': response_data.get('contact_no', ''),
#                 'email_id': response_data.get('email_id', ''),
#                 'date_of_birth': response_data.get('date_of_birth', ''),
#                 'fathers_name': response_data.get('fathers_name', ''),
#                 'fathers_contact_no': response_data.get('fathers_contact_no', ''),
#                 'fathers_occupation': response_data.get('fathers_occupation', ''),
#                 'address': response_data.get('address', ''),
#                 'status': response_data.get('status', ''),
#                 'course_name': response_data.get('course_name', ''),
#                 'inplant_technology': response_data.get('inplant_technology', ''),
#                 'inplant_no_of_days': response_data.get('inplant_no_of_days', ''),
#                 'inplant_no_of_students': response_data.get('inplant_no_of_students', ''),
#                 'internship_technology': response_data.get('internship_technology', ''),
#                 'internship_no_of_days': response_data.get('internship_no_of_days', ''),
#                 'next_follow_up_date': response_data.get('next_follow_up_date', ''),
#                 'degree': response_data.get('degree', ''),
#                 'college': response_data.get('college', ''),
#                 'grade_percentage': response_data.get('grade_percentage', ''),
#                 'year_of_graduation': response_data.get('year_of_graduation', ''),
#                 'mode_of_enquiry': response_data.get('mode_of_enquiry', ''),
#                 'reference_name': response_data.get('reference_name', ''),
#                 'reference_contact_no': response_data.get('reference_contact_no', ''),
#                 'other_enquiry_details': response_data.get('other_enquiry_details', ''),
#                 'courses': courses,
#                 'mode_of_enquiry_choices': mode_of_enquiry_choices,
#             }
#             return render(request, 'new_enquiry.html', context)
        
#     # Fetch available courses and mode of enquiry choices for the form
#     courses = Course.objects.all()
#     mode_of_enquiry_choices = Enquiry_Mode.objects.all()

#     context = {
#         'courses': courses,
#         'mode_of_enquiry_choices': mode_of_enquiry_choices,
#         'enquiry_no': new_enquiry_no
#     }
    
#     return render(request, 'new_enquiry.html', context)

def generate_new_enquiry_no():
    try:
        last_enquiry = Enquiry.objects.latest('id')
        last_enquiry_no = last_enquiry.enquiry_no
    except Enquiry.DoesNotExist:
        last_enquiry_no = "EWT-0000" 

    numeric_part = int(last_enquiry_no.split('-')[1])
    incremented_numeric_part = numeric_part + 1
    return f"EWT-{incremented_numeric_part:04d}"

def add_attribute_view(request):
    if request.method == 'POST':
        # Extract data from the form
        mode_of_enquiry = request.POST.get("mode_of_enquiry", "").strip()
        
        # Prepare data for the API request
        user_data = {
            'mode_of_enquiry': mode_of_enquiry.lower(),
        }

        # Get the token
        try:
            token = Token.objects.get(user=request.user)
        except Token.DoesNotExist:
            context = {
                'error': 'Authentication token not found'
            }
            return render(request, 'add_attribute.html', context)
        
        api_url = 'http://127.0.0.1:8000/api/enquiry_mode/'
        headers = {
            'Authorization': f'Token {token.key}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(api_url, json=user_data, headers=headers)
            response_data = response.json()
            
            print(response_data)
            
        except requests.exceptions.HTTPError as http_err:
            # Handle specific HTTP errors
            context = {
                'error': f'HTTP error occurred: {http_err}',
                'response_data': response.json()
            }
            return render(request, 'add_attribute.html', context)
        except requests.exceptions.RequestException as req_err:
            # Handle general request exceptions
            print(f'Error during API create Course: {req_err}')
            context = {
                'error': 'An error occurred while creating course.'
            }
            return render(request, 'add_attribute.html', context)        
        
        if response.status_code == 201:
            context =  {
                "message": "New Enquiry Mode Created Successfully"
            }
            return render(request, 'add_attribute.html', context)
        else:
            context = {
                'course': response_data.get('mode_of_enquiry', ''),
            }
            return render(request, 'add_attribute.html', context)
    return render(request, 'add_attribute.html')

def manage_attribute_view(request):
    # Fetch the token
    try:
        token = Token.objects.get(user=request.user)  # Assuming you only have one token and it's safe to get the first one
    except Token.DoesNotExist:
        context = {
            'error': 'Authentication token not found'
        }
        return render(request, 'manage_attributes.html', context)
    
    api_url = 'http://127.0.0.1:8000/api/enquiry_mode/'
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        response_data = response.json()
        
        print(response_data)
        
    except requests.exceptions.RequestException as err:
        # Catch any request-related exceptions
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'manage_attributes.html', context)

    # Get the per_page value from the request, default to 10 if not provided
    per_page = request.GET.get('per_page', '10')

    # Apply pagination
    paginator = Paginator(response_data, per_page)  # Use response_data for pagination
    
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'per_page': per_page,
    }
    return render(request, 'manage_attributes.html', context)

def delete_attribute_view(request, id):
    user_id = Enquiry_Mode.objects.get(id=id)
    
    print(user_id)
    
    if not user_id:
        context = {'error': 'Attribute ID not provided'}
        return render(request, 'manage_attributes.html', context)
    
    try:
        token = Token.objects.get(user=request.user)  # Get the first token for simplicity
        if not token:
            raise Token.DoesNotExist
    except Token.DoesNotExist:
        context = {'error': 'Authentication token not found'}
        return render(request, 'manage_attributes.html', context)
    
    api_url = f'http://127.0.0.1:8000/api/enquiry_mode/{user_id.pk}/'
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.delete(api_url, headers=headers)
        response.raise_for_status()

    except requests.exceptions.RequestException as err:
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'manage_attributes.html', context)
    
    if response.status_code == 204:
        return redirect('manage_attribute')
    
    else:
        response_data = response.json()
        context = {
            'detail': response_data.get('detail', 'An error occurred while deleting the Attributes'),
        }
        return render(request, 'manage_attributes.html', context)

def delete_all_attributes_view(request):
    if request.method == 'POST':
        print("Welcome")
        try:
            data = json.loads(request.body)
            
            print("Data : ", data)
            
            user_ids = data.get('user_ids', [])
            
            if user_ids:
                Enquiry_Mode.objects.filter(id__in=user_ids).delete()
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'error': 'No Enquiry selected for deletion'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

# update_attribute_view
def update_attribute_view(request, id):
    try:
        user = Enquiry_Mode.objects.get(id=id)
    except Enquiry_Mode.DoesNotExist:
        context = {'error': 'Attributes not found'}
        return render(request, 'manage_attributes.html', context)

    if request.method == 'POST':
        
        try:
            token = Token.objects.first()  # Get the first token for simplicity
            if not token:
                raise Token.DoesNotExist
        except Token.DoesNotExist:
            context = {'error': 'Authentication token not found'}
            return render(request, 'manage_attributes.html', context)
        
        api_url = f'http://127.0.0.1:8000/api/update_enquiry_mode/{user.pk}/'
        headers = {
            'Authorization': f'Token {token.key}',
            'Content-Type': 'application/json'
        }
        
        user_data = {
            'mode_of_enquiry': request.POST.get('attribute', user.mode_of_enquiry),
        }

        try:
            response = requests.patch(api_url, data=json.dumps(user_data), headers=headers)
            print("API Response Status Code:", response.status_code)
            response.raise_for_status()
            response_data = response.json()
            print("API Response Data:", response_data)
        except requests.exceptions.RequestException as err:
            context = {
                'error': f'Request error occurred: {err}',
                'response_data': response.json() if response.content else {}
            }
            return render(request, 'manage_attributes.html', context)
        
        if response.status_code in [200, 204]:  # 204 No Content is also a valid response for updates
            print("Update successful")
            return redirect('manage_attribute')
        else:
            context = {
                'error': 'Failed to update user information',
                'mode_of_enquiry': response_data.get('mode_of_enquiry', ''),
            }
            return render(request, 'update_attributes.html', context)
        
    return render(request, 'update_attributes.html', {"enquiry_mode": user})


# csv file formate for attributes
@csrf_exempt
def export_attributes_csv(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')  # Get the ids from AJAX request

        # Create the HttpResponse object with the appropriate CSV header
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="attributes_list_csv.csv"'

        writer = csv.writer(response)

        # Write the header row
        writer.writerow(['Attributes Name'])

        # Fetch selected courses based on IDs
        selected_attributes = Enquiry_Mode.objects.filter(id__in=ids)

        for user in selected_attributes:        
            # Write the data row
            writer.writerow([user.mode_of_enquiry])

        return response

    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX

# Excel file format for course
@csrf_exempt
def export_attributes_excel(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')  # Get the ids from AJAX request

        # Fetch selected courses based on IDs
        selected_attributes = Enquiry_Mode.objects.filter(id__in=ids)

        # Create an Excel workbook
        wb = openpyxl.Workbook()
        ws = wb.active

        # Define header row with font style and alignment
        header_row = ['Attributes Name']
        ws.append(header_row)

        for idx, user in enumerate(selected_attributes, start=2):
            ws.append([user.mode_of_enquiry])

        # Create an in-memory file-like object to save the workbook
        output = BytesIO()
        wb.save(output)
        output.seek(0)

        # Create the HTTP response with Excel content type and attachment header
        response = HttpResponse(output, content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="generated_excel.xlsx"'
        
        return response

    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX

@csrf_protect
@require_POST
def export_attributes_pdf(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')
        selected_attribute = Enquiry_Mode.objects.filter(id__in=ids)
        
        if not selected_attribute:
            return JsonResponse({'error': 'No users available.'}, status=404)
        
        attribute_list = []
        for user in selected_attribute:    
            attribute_list.append({
                'mode_of_enquiry': user.mode_of_enquiry, 
            })
        
        print(attribute_list)
        
        content = {'attribute_list': attribute_list}
        return renderers.render_to_pdf('attribute_data_list.html', content)
    
    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX

class SearchAttributeResultsView(ListView):
    model = Enquiry_Mode
    template_name = 'search_attribute_result.html'

    def get_queryset(self):
        query = self.request.GET.get("q")
        
        object_list = Enquiry_Mode.objects.filter(
            Q(mode_of_enquiry__icontains = query)
        )
        
        return object_list

# Enquiry view

def enquiry_view(request):
    new_enquiry_no = generate_new_enquiry_no()

    if request.method == 'POST':
        try:
            inplant_no_of_days = int(request.POST.get('inplant_no_of_days', 0)) if request.POST.get('inplant_no_of_days') else None
            inplant_no_of_students = int(request.POST.get('inplant_no_of_students', 0)) if request.POST.get('inplant_no_of_students') else None
            internship_no_of_students = int(request.POST.get('internship_no_of_students', 0)) if request.POST.get('internship_no_of_students') else None
            internship_no_of_days = int(request.POST.get('internship_no_of_days', 0)) if request.POST.get('internship_no_of_days') else None
            year_of_graduation = int(request.POST.get('year_of_graduation', 0)) if request.POST.get('year_of_graduation') else None
        except ValueError:
            # Handle invalid integer or float conversion
            inplant_no_of_days = None
            inplant_no_of_students = None
            internship_no_of_students = None
            internship_no_of_days = None
            year_of_graduation = None

        enquiry_data = {
            'enquiry_date': request.POST.get('enquiry_date', '').strip(),
            'enquiry_no': new_enquiry_no,
            'name': request.POST.get('student_name', '').strip(),
            'contact_no': request.POST.get('contact', '').strip(),
            'email_id': request.POST.get('email', '').strip(),
            'date_of_birth': request.POST.get('dob', '').strip(),
            'fathers_name': request.POST.get('father_name', '').strip(),
            'fathers_contact_no': request.POST.get('father_contact', '').strip(),
            'fathers_occupation': request.POST.get('fathers_occupation', '').strip(),
            'address': request.POST.get('address', '').strip(),
            'status': request.POST.get('status', '').strip(),
            'course_name': request.POST.get('course_name', '').strip(),
            'inplant_technology': request.POST.get('inplant_technology', '').strip(),
            'inplant_no_of_days': inplant_no_of_days,
            'inplant_no_of_students': inplant_no_of_students,
            'internship_technology': request.POST.get('internship_technology', '').strip(),
            'internship_no_of_days': internship_no_of_days,
            'internship_no_of_students': internship_no_of_students,
            'next_follow_up_date': request.POST.get('next_follow_up_date', '').strip(),
            'degree': request.POST.get('degree', '').strip(),
            'college': request.POST.get('college', '').strip(),
            'grade_percentage': request.POST.get('grade_percentage', '').strip(),
            'year_of_graduation': year_of_graduation,
            'mode_of_enquiry': request.POST.get('mode_of_enquiry', '').strip(),
            'reference_name': request.POST.get('reference_name', '').strip(),
            'reference_contact_no': request.POST.get('reference_contact', '').strip(),
            'other_enquiry_details': request.POST.get('other_enquiry_details', '').strip(),
            'lead_type': request.POST.get('lead_type', '').strip(),
        }

        # Get the token
        try:
            token = Token.objects.get(user=request.user)
        except Token.DoesNotExist:
            context = {
                'error': 'Authentication token not found',
                **enquiry_data,
            }
            return render(request, 'new_enquiry.html', context)
        
        api_url = 'http://127.0.0.1:8000/api/enquiry/'
        headers = {
            'Authorization': f'Token {token.key}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(api_url, json=enquiry_data, headers=headers)
            response_data = response.json()
            print(response_data)
            
        except requests.exceptions.RequestException:
            context = {
                'error': 'An error occurred while creating the enquiry.',
                **enquiry_data,
            }
            return render(request, 'new_enquiry.html', context)        
        
        if response.status_code == 201:
            messages.success(request, 'Created Successfully')
            return redirect('enquiry')
        else:
            # Handle API error messages
            error_message = response_data.get('error', 'An error occurred during enquiry creation.')
            errors = response_data
            
            print(errors)
            
            courses = Course.objects.all()
            mode_of_enquiry_choices = Enquiry_Mode.objects.all()
            context = {
                'error': error_message,
                'errors': errors,
                **enquiry_data,
                'courses': courses,
                'mode_of_enquiry_choices': mode_of_enquiry_choices,
            }
            return render(request, 'new_enquiry.html', context)
    
    courses = Course.objects.all()
    mode_of_enquiry_choices = Enquiry_Mode.objects.all()

    context = {
        'courses': courses,
        'mode_of_enquiry_choices': mode_of_enquiry_choices,
        'enquiry_no': new_enquiry_no
    }
    
    return render(request, 'new_enquiry.html', context)


def manage_enquiry_view(request):
    # Fetch the token
    
    enquiry_data = Enquiry_Mode.objects.all().values()
    
    course = Course.objects.all().values()
    
    try:
        token = Token.objects.get(user=request.user)  # Assuming you only have one token and it's safe to get the first one
    except Token.DoesNotExist:
        context = {
            'error': 'Authentication token not found'
        }
        return render(request, 'manage_user.html', context)
    
    api_url = 'http://127.0.0.1:8000/api/enquiry/'
    
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        response_data = response.json()
        
    except requests.exceptions.RequestException as err:
        # Catch any request-related exceptions
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'manage_user.html', context)

    # Get the per_page value from the request, default to 10 if not provided
    per_page = request.GET.get('per_page', '10')

    # Apply pagination
    paginator = Paginator(response_data, per_page)  # Use response_data for pagination
    
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'per_page': per_page,
        'course_name': course,
        'enquiry': enquiry_data,
    }
    return render(request, 'manage_enquiry.html', context)

def update_enquiry_view(request, id):
    try:
        enquiry = Enquiry.objects.get(id=id)
    except Enquiry.DoesNotExist:
        context = {'error': 'Enquiry not found'}
        return render(request, 'manage_enquiry.html', context)

    if request.method == 'POST':
        print("Welcome")
        
        try:
            token = Token.objects.get(user=request.user)  # Get the first token for simplicity
            print(token)
            if not token:
                raise Token.DoesNotExist
        except Token.DoesNotExist:
            context = {'error': 'Authentication token not found'}
            return render(request, 'manage_enquiry.html', context)
        
        api_url = f'http://127.0.0.1:8000/api/update_enquiry/{enquiry.pk}/'
        
        print("Api URL : ", api_url)
        
        headers = {
            'Authorization': f'Token {token.key}',
        }
        
        # Prepare the data
        enquiry_data = {
            'enquiry_date': request.POST.get('enquiry_date', enquiry.enquiry_date),
            'enquiry_no': request.POST.get('enquiry_no', enquiry.enquiry_no),
            'name': request.POST.get('student_name', enquiry.name),
            'contact_no': request.POST.get('contact', enquiry.contact_no),
            'email_id': request.POST.get('email', enquiry.email_id),
            'date_of_birth': request.POST.get('dob', enquiry.date_of_birth),
            'fathers_name': request.POST.get('father_name', enquiry.fathers_name),
            'fathers_contact_no': request.POST.get('father_contact', enquiry.fathers_contact_no),
            'fathers_occupation': request.POST.get('fathers_occupation', enquiry.fathers_occupation),
            'address': request.POST.get('address', enquiry.address),
            # 'status': request.POST.get('status', enquiry.status),
            'course_name': request.POST.get('course_name', enquiry.course_name),
            'inplant_technology': request.POST.get('technology', enquiry.inplant_technology),
            'inplant_no_of_days': request.POST.get('inplant_no_of_days', enquiry.inplant_no_of_days),
            'inplant_no_of_students': request.POST.get('inplant_no_of_students', enquiry.inplant_no_of_students),
            'internship_technology': request.POST.get('internship_technology', enquiry.internship_technology),
            'internship_no_of_days': request.POST.get('internship_no_of_days', enquiry.internship_no_of_days),
            'next_follow_up_date': request.POST.get('next_follow_up_date', enquiry.next_follow_up_date),
            'degree': request.POST.get('degree', enquiry.degree),
            'college': request.POST.get('college', enquiry.college),
            'grade_percentage': request.POST.get('grade_percentage', enquiry.grade_percentage),
            'year_of_graduation': request.POST.get('year_of_graduation', enquiry.year_of_graduation),
            'mode_of_enquiry': request.POST.get('mode_of_enquiry', enquiry.mode_of_enquiry),
            'reference_name': request.POST.get('reference_name', enquiry.reference_name),
            'reference_contact_no': request.POST.get('reference_contact', enquiry.reference_contact_no),
            'other_enquiry_details': request.POST.get('other_enquiry_details', enquiry.other_enquiry_details),
            'notes': request.POST.get('notes', enquiry.notes),
            'status': request.POST.get('notes', enquiry.notes),
            'lead_type': request.POST.get('lead_type', enquiry.lead_type),
        }
        
        files = {}
        if 'files' in request.FILES:
            files = {'files': request.FILES['files']}
        else:
            files = {'files': enquiry.files} # Or handle the case when no new file is uploaded
            
        # Log the data and files to be sent
        print("Enquiry Data:", enquiry_data)
        print("Files Data:", files)
        
        try:
            response = requests.patch(api_url, data=enquiry_data, files=files, headers=headers)
            print("API Response Status Code:", response.status_code)
            response.raise_for_status()
            response_data = response.json()
            print("API Response Data:", response_data)
        except requests.exceptions.RequestException as err:
            print(f'Request error occurred: {err}')
            context = {
                'error': f'Request error occurred: {err}',
                'response_data': response.json() if response.content else {}
            }
            return render(request, 'manage_enquiry.html', context)
        
        if response.status_code in [200, 204]:  # 204 No Content is also a valid response for updates
            # notes_content = request.POST.get('notes', '')
            # uploaded_file = request.FILES.get('files', None)
            notes_content = request.POST.get('notes', '')
            uploaded_file = request.FILES.get('files', None)
            
            print("Notes Content : ", notes_content)
            
            print("Notes File : ", uploaded_file)
            
            if notes_content or uploaded_file:
                notes_data = Notes.objects.create(
                    notes=notes_content,
                    files=uploaded_file,
                    user_id = enquiry.pk,
                    created_by=request.user.id,  # Assuming the request user is authenticated
                    modified_by=request.user.id
                )
                
                print(notes_data)
                
                notes_data.save()
            print("Update successful")
            return redirect('manage_enquiry')
        else:
            context = {
                'error': response_data.get('error', 'An error occurred during enquiry creation.'),
                'enquiry_data': enquiry_data,
                'files': files.get('files', ''),
            }
            return render(request, 'update_enquiry.html', context)
    
    courses = Course.objects.all()
    notes = Notes.objects.all().values().order_by("-created_at")
    mode_of_enquiry = Enquiry_Mode.objects.all()
    
    context = {
        'courses': courses,
        'mode_of_enquiry': mode_of_enquiry,
        "enquiry": enquiry,
        "notes": notes,
        "enquiry_id": id,
    }    
        
    return render(request, 'update_enquiry.html', context)


# def delete_enquiry_view(request, id):
#     user_id = Enquiry.objects.get(id=id)
    
#     print(user_id.pk)
    
#     if not user_id:
#         context = {'error': 'Enquiry ID not provided'}
#         return render(request, 'manage_enquiry.html', context)
    
#     try:
#         token = Token.objects.get(user=request.user)  # Get the first token for simplicity
#         if not token:
#             raise Token.DoesNotExist
#     except Token.DoesNotExist:
#         context = {'error': 'Authentication token not found'}
#         return render(request, 'manage_enquiry.html', context)
    
#     api_url = f'http://127.0.0.1:8000/api/enquiry/{user_id.pk}/'
#     headers = {
#         'Authorization': f'Token {token.key}',
#         'Content-Type': 'application/json'
#     }
    
#     try:
#         response = requests.delete(api_url, headers=headers)
#         response.raise_for_status()

#     except requests.exceptions.RequestException as err:
#         context = {
#             'error': f'Request error occurred: {err}',
#             'response_data': response.json() if response else {}
#         }
#         return render(request, 'manage_enquiry.html', context)
    
#     if response.status_code == 200:
#         print("enquiry")
#         return redirect('manage_enquiry')
    
#     else:
#         response_data = response.json()
#         context = {
#             'detail': response_data.get('detail', 'An error occurred while deleting the Enquiry'),
#         }
#         return render(request, 'manage_enquiry.html', context)

def delete_enquiry_view(request, id):
    user_id = Enquiry.objects.get(id=id)
    
    print(user_id.pk)
    
    if not user_id:
        context = {'error': 'Enquiry ID not provided'}
        return render(request, 'manage_enquiry.html', context)
    
    try:
        token = Token.objects.get(user=request.user)  # Get the first token for simplicity
        if not token:
            raise Token.DoesNotExist
    except Token.DoesNotExist:
        context = {'error': 'Authentication token not found'}
        return render(request, 'manage_enquiry.html', context)
    
    api_url = f'http://127.0.0.1:8000/api/delete_enquiry/{user_id.pk}/'
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.delete(api_url, headers=headers)
        response.raise_for_status()
        
        if response.status_code == 200:
            messages.success(request, 'Successfully Deleted')
            return redirect('manage_enquiry')

    except requests.exceptions.RequestException as err:
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'manage_enquiry.html', context)
    
def delete_all_enquiry_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            print("Data : ", data)
            
            user_ids = data.get('user_ids', [])
            
            print("User ID : ", user_ids)
            
            if user_ids:
                Enquiry.objects.filter(id__in=user_ids).delete()
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'error': 'No users selected for deletion'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON'})
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

# csv file formate for attributes
@csrf_exempt
def export_enquiry_csv(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')  # Get the ids from AJAX request

        # Create the HttpResponse object with the appropriate CSV header
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="attributes_list_csv.csv"'

        writer = csv.writer(response)

        # Write the header row with capitalized first letters
        writer.writerow([
            'Enquiry Date', 'Enquiry No', 'Name', 'Contact No', 'Course Name', 'Next Follow Up Date', 
            'Mode of Enquiry', 'Lead Type', 'Status'
        ])

        # Fetch selected enquiries based on IDs
        selected_enquiries = Enquiry.objects.filter(id__in=ids)

        for enquiry in selected_enquiries:
            writer.writerow([
                enquiry.enquiry_date,
                enquiry.enquiry_no,
                enquiry.name,
                int(enquiry.contact_no),
                enquiry.course_name.course_name if enquiry.course_name else '',  # Use the course name
                enquiry.next_follow_up_date,
                enquiry.mode_of_enquiry.mode_of_enquiry if enquiry.mode_of_enquiry else '',  # Use the mode of enquiry name
                enquiry.lead_type,
                enquiry.status
            ])

        return response

    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX

# Excel file format for course
@csrf_exempt
def export_enquiry_excel(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')  # Get the ids from AJAX request

        # Fetch selected courses based on IDs
        selected_attributes = Enquiry.objects.filter(id__in=ids)
        
        if not selected_attributes:
            return JsonResponse({'error': 'No Enquires available.'}, status=404)

        # Create an Excel workbook
        wb = openpyxl.Workbook()
        ws = wb.active

        # Define header row with font style and alignment
        # Define header row with capitalized first letters
        headers = [
            'Enquiry Date', 'Enquiry No', 'Name', 'Contact No',
            'Course Name', 'Next Follow Up Date',
            'Mode of Enquiry', 'Lead Type', 'Status'
        ]
        
        # Append the header row to the sheet
        ws.append(headers)

        for enquiry in selected_attributes:
            ws.append([
                enquiry.enquiry_date.strftime('%Y-%m-%d') if enquiry.enquiry_date else '',
                enquiry.enquiry_no,
                enquiry.name,
                int(enquiry.contact_no),
                enquiry.course_name.course_name if enquiry.course_name else '',
                enquiry.next_follow_up_date.strftime('%Y-%m-%d') if enquiry.next_follow_up_date else '',
                enquiry.mode_of_enquiry.mode_of_enquiry if enquiry.mode_of_enquiry else '',
                enquiry.lead_type,
                enquiry.status
            ])

        # Create an in-memory file-like object to save the workbook
        output = BytesIO()
        wb.save(output)
        output.seek(0)

        # Create the HTTP response with Excel content type and attachment header
        response = HttpResponse(output, content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="generated_excel.xlsx"'
        
        return response

    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX

@csrf_protect
@require_POST
def export_enquiry_pdf(request):
    if request.method == 'POST':
        ids = request.POST.get('ids', '').split(',')
        selected_attribute = Enquiry.objects.filter(id__in=ids)
        
        if not selected_attribute:
            return JsonResponse({'error': 'No users available.'}, status=404)
        
        attribute_list = []
        for enquiry in selected_attribute:    
            attribute_list.append({
                'enquiry_date': enquiry.enquiry_date.strftime('%Y-%m-%d') if enquiry.enquiry_date else '',
                'enquiry_no': enquiry.enquiry_no,
                'name': enquiry.name,
                'contact_no': enquiry.contact_no,
                'email_id': enquiry.email_id,
                'date_of_birth': enquiry.date_of_birth.strftime('%Y-%m-%d') if enquiry.date_of_birth else '',
                'fathers_name': enquiry.fathers_name,
                'fathers_contact_no': enquiry.fathers_contact_no,
                'fathers_occupation': enquiry.fathers_occupation,
                'address': enquiry.address,
                'status': enquiry.status,
                'course_name': enquiry.course_name.course_name if enquiry.course_name else '',
                'inplant_technology': enquiry.inplant_technology,
                'inplant_no_of_days': enquiry.inplant_no_of_days if enquiry.inplant_no_of_days is not None else '',
                'inplant_no_of_students': enquiry.inplant_no_of_students if enquiry.inplant_no_of_students is not None else '',
                'internship_technology': enquiry.internship_technology,
                'internship_no_of_days': enquiry.internship_no_of_days if enquiry.internship_no_of_days is not None else '',
                'next_follow_up_date': enquiry.next_follow_up_date.strftime('%Y-%m-%d') if enquiry.next_follow_up_date else '',
                'degree': enquiry.degree,
                'college': enquiry.college,
                'grade_percentage': enquiry.grade_percentage if enquiry.grade_percentage is not None else '',
                'year_of_graduation': enquiry.year_of_graduation if enquiry.year_of_graduation is not None else '',
                'mode_of_enquiry': enquiry.mode_of_enquiry.mode_of_enquiry if enquiry.mode_of_enquiry else '',
                'reference_name': enquiry.reference_name,
                'reference_contact_no': enquiry.reference_contact_no,
                'other_enquiry_details': enquiry.other_enquiry_details,
                'lead_type': enquiry.lead_type
            })        
        content = {'enquiry_list': attribute_list}
        return renderers.render_to_pdf('enquiry_data_list.html', content)
    
    # Handle GET request or non-AJAX POST request here if needed
    return HttpResponse(status=400)  # Bad request if not POST or AJAX

class SearchEnquiryResultsView(ListView):
    model = Enquiry
    template_name = 'search_enquiry_result.html'

    def get_queryset(self):
        query = self.request.GET.get("q", "")
        start_date = self.request.GET.get("start_date", "")
        end_date = self.request.GET.get("end_date", "")

        object_list = Enquiry.objects.all()

        # Apply text search if query is provided
        if query:
            object_list = object_list.filter(
                Q(enquiry_no__icontains=query) |
                Q(name__icontains=query) |
                Q(contact_no__icontains=query) |
                Q(course_name__course_name__icontains=query) |
                Q(mode_of_enquiry__mode_of_enquiry__icontains=query) |
                Q(status__icontains=query) |
                Q(lead_type__icontains=query)
            )

        # Apply date range filter if dates are provided
        if start_date and end_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                object_list = object_list.filter(enquiry_date__range=(start_date, end_date))
            except ValueError:
                pass  # Handle invalid date format if necessary

        return object_list
    
    
def delete_notes_view(request, id):
    user_id = Notes.objects.get(id=id)
    
    print(user_id)
    
    if not user_id:
        context = {'error': 'Attribute ID not provided'}
        return render(request, 'update_enquiry.html', context)
    
    try:
        token = Token.objects.get(user=request.user)  # Get the first token for simplicity
        if not token:
            raise Token.DoesNotExist
    except Token.DoesNotExist:
        context = {'error': 'Authentication token not found'}
        return render(request, 'update_enquiry.html', context)
    
    api_url = f'http://127.0.0.1:8000/api/delete_notes/{user_id.pk}/'
    headers = {
        'Authorization': f'Token {token.key}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.delete(api_url, headers=headers)
        response.raise_for_status()
        
        if response.status_code == 200:
            return redirect('manage_enquiry')
    except requests.exceptions.RequestException as err:
        context = {
            'error': f'Request error occurred: {err}',
            'response_data': response.json() if response else {}
        }
        return render(request, 'update_enquiry.html', context)
    

def update_notes_view(request, id):
    try:
        user = Notes.objects.get(id=id)
    except Notes.DoesNotExist:
        context = {'error': 'Notes not found'}
        return render(request, 'update_enquiry.html', context)

    if request.method == 'POST':
        try:
            token = Token.objects.get(user=request.user)
            if not token:
                raise Token.DoesNotExist
        except Token.DoesNotExist:
            context = {'error': 'Authentication token not found'}
            return render(request, 'update_enquiry.html', context)
        
        api_url = f'http://127.0.0.1:8000/api/update_notes/{user.pk}/'
        headers = {
            'Authorization': f'Token {token.key}',
        }
        
        files = {}
        if 'files' in request.FILES:
            files['files'] = request.FILES['files']
        
        user_data = {
            'notes': request.POST.get('notes', user.notes),
        }

        try:
            response = requests.patch(api_url, data=user_data, files=files, headers=headers)
            response.raise_for_status()
            response_data = response.json()
        except requests.exceptions.RequestException as err:
            context = {
                'error': f'Request error occurred: {err}',
                'response_data': response.json() if response.content else {}
            }
            return render(request, 'update_enquiry.html', context)
        
        if response.status_code == 200:  # 204 No Content is also a valid response for updates
            print("Update successful")
            return redirect('manage_enquiry')
        else:
            context = {
                'error': 'Failed to update user information',
                'notes': response_data.get('notes', ''),
            }
            return render(request, 'update_enquiry.html', context)
        
    return render(request, 'update_notes.html')
