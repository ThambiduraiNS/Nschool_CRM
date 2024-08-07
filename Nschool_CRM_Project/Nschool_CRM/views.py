
from io import BytesIO
import json, requests

from django.shortcuts import redirect, render
from django.contrib.auth import authenticate
from django.contrib.auth import authenticate, login , logout as auth_logout
from django.template import RequestContext
from yaml import Loader
from .models import NewUser
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

# Create your views here.
# @csrf_protect
# def admin_login(request):
#     if request.method == 'POST':
#         username = request.POST.get("username", "").strip()
#         password = request.POST.get("password", "").strip()

#         if not username or not password:
#             context = {
#                 'error': 'Username and password are required.'
#             }
#             return render(request, 'admin_login.html', context)
        
#         user = authenticate(request, username=username, password=password)
        
#         if user is not None:
#             # Create new token (deleting old token is optional, based on your use case)
#             Token.objects.filter(user=user).delete()  # Optional: delete old token
#             token, created = Token.objects.get_or_create(user=user)
            
#             # Optionally store the token in the session or pass it to the next page
#             request.session['auth_token'] = token.key  # Example of storing in session
            
#             return redirect('dashboard') 
#         else:
#             context = {
#                 'error': 'Invalid credentials.'
#             }
#             return render(request, 'admin_login.html', context)
    
#     return render(request, 'admin_login.html')
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



# def logout(request):
#     user = request.user.authenticate
#     print("User name : ",user)
    
#     if not user.is_authenticated:
#         return redirect('admin_login')
    
#     token = Token.objects.get(user=user)
#     print(token)
#     api_url = 'http://127.0.0.1:8000/api/logout/'
    
#     headers = {
#         'Authorization': f'Token {token.key}'
#     }
    
#     try:
#         response = requests.post(api_url, headers=headers)
#         response.raise_for_status()
#     except requests.exceptions.RequestException as e:
#         print(f'Error during API logout: {e}')
#         return redirect('dashboard')  # Redirect to dashboard or show an error message

#     # Remove the token locally after successful API logout
#     token.delete()

#     # Clear the session and redirect to the login page
#     request.session.flush()
#     return redirect('admin_login')


def logout(request):
    # user = request.user
    # print(user)
    # if not user.is_authenticated():
    #     return redirect('admin_login')

    # try:
    #     token = Token.objects.get(user=user)
    #     print(f"Token for user {user}: {token.key}")
    # except Token.DoesNotExist:
    #     print(f"No token found for user {user}")
    #     return redirect('admin_login')  # Or handle this case as needed
    
    
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


# def user_module_view(request): 
#     if request.method == 'POST':
#         username = request.POST.get("username", "").strip()
#         email = request.POST.get("email", "").strip()
#         contact = request.POST.get("contact", "").strip()
#         designation = request.POST.get("designation", "").strip()
#         password = request.POST.get("password", "").strip()
#         cpassword = request.POST.get("cpassword", "").strip()
        
#         # Get checkbox values
#         permissions = {
#             "enquiry": "Enquiry" in request.POST,
#             "enrollment": "Enrollment" in request.POST,
#             "attendance": "Attendance" in request.POST,
#             "staff": "Staff" in request.POST,
#             "placement": "Placement" in request.POST,
#             "report": "Report" in request.POST,
#         }

#         if password == cpassword:
#             newuser = NewUser(
#                 name=username,
#                 email=email,
#                 contact=contact,
#                 designation=designation,
#                 password=password,
#                 enquiry=permissions["enquiry"],
#                 enrollment=permissions["enrollment"],
#                 attendance=permissions["attendance"],
#                 staff=permissions["staff"],
#                 placement=permissions["placement"],
#                 report=permissions["report"],
#             )
            
#             newuser.save()
#             return redirect('manage-user')
    
#     return render(request, 'new_user.html')

# def user_module_view(request): 
#     if request.method == 'POST':
        # username = request.POST.get("username", "").strip()
        # email = request.POST.get("email", "").strip()
        # contact = request.POST.get("contact", "").strip()
        # designation = request.POST.get("designation", "").strip()
        # password = request.POST.get("password", "").strip()
        # cpassword = request.POST.get("cpassword", "").strip()
        
        # # Get checkbox values
        # permissions = {
        #     "enquiry": "Enquiry" in request.POST,
        #     "enrollment": "Enrollment" in request.POST,
        #     "attendance": "Attendance" in request.POST,
        #     "staff": "Staff" in request.POST,
        #     "placement": "Placement" in request.POST,
        #     "report": "Report" in request.POST,
        # }

        # if password == cpassword:
        #     newuser = NewUser(
        #         name=username,
        #         email=email,
        #         contact=contact,
        #         designation=designation,
        #         password=password,
        #         enquiry=permissions["enquiry"],
        #         enrollment=permissions["enrollment"],
        #         attendance=permissions["attendance"],
        #         staff=permissions["staff"],
        #         placement=permissions["placement"],
        #         report=permissions["report"],
        #     )
        
    #     token = Token.objects.get()
    #     api_url = 'http://127.0.0.1:8000/api/newuser/'
    #     headers = {
    #         'Authorization': f'Token {token.key}'
    #     }
        
    #     try:
    #         response = requests.post(api_url, headers=headers)
    #         # response.raise_for_status()
    #         response_data = response.json()
    #     except requests.exceptions.RequestException as e:
    #         print(f'Error during API create New User: {e}')   
    #         return redirect('user-module')
        
    #     if response.status_code == 200:
    #         return redirect('manage-user')
    #     else:
    #         context = {
    #             'error': response_data.get('user_error', response_data.get('pass_error', response_data.get('error', 'Invalid credentials')))
    #         }
    #         return render(request, 'admin_login.html', context)
        
    # return render(request, 'new_user.html')

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


# def manage_user_view(request):
#     # Fetch all users or the relevant queryset
#     users_list = NewUser.objects.all().order_by('-id')
    
#     # Get the per_page value from the request, default to 10 if not provided
#     per_page = request.GET.get('per_page', '10')

#     # Apply pagination
#     paginator = Paginator(users_list, per_page)  # Show per_page users per page
    
#     page_number = request.GET.get('page')
#     page_obj = paginator.get_page(page_number)

#     context = {
#         'page_obj': page_obj,
#         'per_page': per_page,
#     }
#     return render(request, 'manage_user.html', context)

# def manage_user_view(request):
#     # Fetch the token
#     try:
#         token = Token.objects.get()  # Assuming you only have one token and it's safe to get the first one
#     except Token.DoesNotExist:
#         context = {
#             'error': 'Authentication token not found'
#         }
#         return render(request, 'new_user.html', context)
    
#     api_url = 'http://127.0.0.1:8000/api/newuser/'
#     headers = {
#         'Authorization': f'Token {token.key}',
#         'Content-Type': 'application/json'
#     }

#     try:
#         response = requests.get(api_url, headers=headers)
#         response.raise_for_status()  # Raise an HTTPError for bad responses
#         response_data = response.json()
        
#         User = get_user_model()
#         for user_data in response_data:
#             raw_password = user_data.get('password')
        
#         passwords = make_password(raw_password)
        
#         print(passwords)
        
#     except requests.exceptions.RequestException as err:
#         # Catch any request-related exceptions
#         context = {
#             'error': f'Request error occurred: {err}',
#             'response_data': response.json() if response else {}
#         }
#         return render(request, 'manage_user.html', context)

#     # Get the per_page value from the request, default to 10 if not provided
#     per_page = request.GET.get('per_page', '10')

#     # Apply pagination
#     paginator = Paginator(response_data, per_page)  # Use response_data for pagination
    
#     page_number = request.GET.get('page')
#     page_obj = paginator.get_page(page_number)

#     context = {
#         'page_obj': page_obj,
#         'per_page': per_page,
#     }
#     return render(request, 'manage_user.html', context)

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
    
        # print("welcome")
        # user_ids = request.POST.getlist('user_ids')  
        # print(f"User IDs received: {user_ids}")  

        # if not user_ids:
        #     context = {'error': 'No user IDs provided'}
        #     return render(request, 'manage_user.html', context)

        # try:
        #     token = Token.objects.first()  # Get the first token for simplicity
        #     if not token:
        #         raise Token.DoesNotExist
        # except Token.DoesNotExist:
        #     context = {'error': 'Authentication token not found'}
        #     return render(request, 'manage_user.html', context)

        # headers = {
        #     'Authorization': f'Token {token.key}',
        #     'Content-Type': 'application/json'
        # }

        # errors = []
        # for user_id in user_ids:
        #     api_url = f'http://127.0.0.1:8000/api/newuser/{user_id}/'
        #     try:
        #         response = requests.delete(api_url, headers=headers)
        #         response.raise_for_status()
        #     except requests.exceptions.RequestException as err:
        #         errors.append({
        #             'user_id': user_id,
        #             'error': f'Request error occurred: {err}',
        #             'response_data': response.json() if response else {}
        #         })

        # if errors:
        #     context = {'errors': errors}
        #     return render(request, 'manage_user.html', context)

        # return redirect('manage-user')
    

    
        # user_ids = request.POST.getlist('user_ids')
        # print(user_ids)
        # if user_ids:
        #     NewUser.objects.filter(id__in=user_ids).delete()
        #     return redirect('manage-users')  # Redirect to a page that lists users
        # else:
        #     context = {'error': 'No users selected for deletion'}
        #     return render(request, 'manage_user.html', context)
        
        
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
    # if request.method == 'POST':
    #     username = request.data.get('username')
    #     password = request.data.get('password')
        
    #     if username == "":
    #         return Response({'user_error': 'Username field is required'}, status=status.HTTP_400_BAD_REQUEST)
        
    #     if password == "":
    #         return Response({'pass_error': 'Password field is required'}, status=status.HTTP_400_BAD_REQUEST)
        
    #     user = authenticate(username=username, password=password)
        
    #     if not user:
    #         return Response({'user_error': 'Username does not exist'}, status=status.HTTP_401_UNAUTHORIZED)

    #     if user:
    #         token, _ = Token.objects.get_or_create(user=user)
    #         return Response({'token': token.key}, status=status.HTTP_200_OK)

    #     return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
    # serializer = UserSerializer(data=request.data)
    # if serializer.is_valid():
    #     user = authenticate(username=serializer.validated_data['username'], password=serializer.validated_data['password'])
    #     token, _ = Token.objects.get_or_create(user=user)
    #     return Response({'token': token.key}, status=status.HTTP_200_OK)
    # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # serializer = UserSerializer(data=request.data)
    
    # print(serializer)
    # if serializer.is_valid():
    #     username_or_email = serializer.validated_data['username_or_email']
    #     password = serializer.validated_data['password']
        
    #     # Log the authentication attempt
    #     logger.debug(f"Attempting to authenticate user: {username_or_email}")
        
    #     # Try to authenticate using custom backend
    #     user = authenticate(request, username=username_or_email, password=password)
        
    #     if user is not None:
    #         token, _ = Token.objects.get_or_create(user=user)
    #         logger.debug(f"Authentication successful for user: {username_or_email}")
    #         return Response({'token': token.key}, status=status.HTTP_200_OK)
    #     else:
    #         logger.debug(f"Authentication failed for user: {username_or_email}")
    #         return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    # else:
    #     logger.debug(f"Invalid data provided: {serializer.errors}")
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
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
    
    
# @csrf_exempt
# def export_courses_csv(request):
#     if request.method == 'POST':
#         try:
#             data = json.loads(request.body)
#             user_ids = data.get('user_ids', [])
            
#             if not user_ids:
#                 return HttpResponse(json.dumps({'success': False, 'error': 'No user IDs provided.'}), content_type='application/json', status=400)

#             # Create the HttpResponse object with the appropriate CSV header
#             response = HttpResponse(content_type='text/csv')
#             response['Content-Disposition'] = 'attachment; filename="course_list_csv.csv"'

#             writer = csv.writer(response)
#             writer.writerow(['name', 'email', 'contact', 'designation'])

#             # Fetch selected users based on IDs
#             selected_users = NewUser.objects.filter(id__in=user_ids)

#             for user in selected_users:
#                 writer.writerow([user.name, user.email, user.contact, user.designation])

#             return response

#         except json.JSONDecodeError:
#             return HttpResponse(json.dumps({'success': False, 'error': 'Invalid JSON format.'}), content_type='application/json', status=400)

#         except Exception as e:
#             return HttpResponse(json.dumps({'success': False, 'error': str(e)}), content_type='application/json', status=500)

#     return HttpResponse(status=400)  # Bad request if not POST

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

        # Create an Excel workbook
        wb = openpyxl.Workbook()
        ws = wb.active

        # Define header row with font style and alignment
        header_row = ['Name', 'Email', 'Contact', 'Designation', 'Permission']
        ws.append(header_row)
        # for cell in ws[1]:
        #     cell.font = Font(bold=True, color='000000')
        #     cell.alignment = Alignment(horizontal='left', vertical='center')

        # Set column widths for better readability
        # column_widths = [20, 30, 50, 20]
        # for i, width in enumerate(column_widths, start=1):
        #     ws.column_dimensions[openpyxl.utils.get_column_letter(i)].width = width

        # Add data rows with alignment and borders
        # thin_border = Border(
        #     left = Side(style='thin'),
        #     right = Side(style='thin'),
        #     top = Side(style='thin'),
        #     bottom = Side(style='thin'),
        # )

        for idx, user in enumerate(selected_courses, start=2):
            # Remove country code from contact number
            
            # Example: Removing country code "+1" (assumes country code is "+1" or "+01")
            # contact_number = str(user.contact)
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
            
            ws.append([user.username, user.email, user.contact, user.designation, ', '.join(permission)])

            # Align text and apply borders
            # for cell in ws[idx]:
            #     cell.alignment = Alignment(horizontal='left', vertical='top', wrap_text=True)
                # cell.border = thin_border

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




# search view
# basic search method
# class SearchResultsView(ListView):
#     model = NewUser
#     template_name = 'search_result.html'
#     def get_queryset(self):
#         query = self.request.GET.get("q")
        
#         object_list = NewUser.objects.filter(
#             Q(name__icontains = query) | 
#             Q(email__icontains = query) |
#             Q(contact__icontains = query) | 
#             Q(designation__icontains = query)
#         )
        
#         return object_list

# class SearchResultsView(ListView):
#     model = NewUser
#     template_name = 'search_result.html'
#     context_object_name = 'users'

#     def get_queryset(self):
#         query = self.request.GET.get("q")
#         if query:
#             fields = [f.name for f in NewUser._meta.fields if isinstance(f, (models.CharField, models.EmailField, PhoneNumberField))]
#             query_filter = Q()
#             for field in fields:
#                 query_filter |= Q(**{f"{field}__icontains": query})
            
#             # Add boolean fields handling
#             boolean_fields = [f.name for f in NewUser._meta.fields if isinstance(f, models.BooleanField)]
            
#             for field in boolean_fields:
#                 if query.lower() in ['true', 'false']:
#                     value = query.lower() == 'true'
                    
#                     query_filter |= Q(**{field: value})
#         else:
#             query_filter = Q(pk__isnull=True)
        
#         object_list = NewUser.objects.filter(query_filter)
#         return object_list


# class SearchResultsView(ListView):
#     model = NewUser
#     template_name = 'search_result.html'
#     context_object_name = 'users'

#     def get_queryset(self):
#         query = self.request.GET.get("q")
#         if query:
#             query_filter = Q()
            
#             # Handle specific keyword searches for boolean fields
#             if 'e'==query.lower() or 'en'==query.lower() or 'enq'==query.lower() or 'enqu'==query.lower() or 'enqui'==query.lower() or 'enquir'==query.lower() or 'enquiry'==query.lower():
#                     query_filter |= Q(enquiry=True)
#             elif query.lower() == 'enrollment':
#                 query_filter |= Q(enrollment=True)
#             elif query.lower() == 'attendance':
#                 query_filter |= Q(attendance=True)
#             elif query.lower() == 'staff':
#                 query_filter |= Q(staff=True)
#             elif query.lower() == 'placement':
#                 query_filter |= Q(placement=True)
#             elif query.lower() == 'report':
#                 query_filter |= Q(report=True)
#             else:
#                 # Search across CharField, EmailField, and PhoneNumberField
#                 fields = [f.name for f in NewUser._meta.fields if isinstance(f, (models.CharField, models.EmailField, PhoneNumberField))]
#                 for field in fields:
#                     query_filter |= Q(**{f"{field}__icontains": query})
#         else:
#             query_filter = Q(pk__isnull=True)
        
#         object_list = NewUser.objects.filter(query_filter)
#         return object_list

class SearchResultsView(ListView):
    model = NewUser
    template_name = 'search_result.html'
    context_object_name = 'users'

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
