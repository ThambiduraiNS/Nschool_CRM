import json, requests
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate
from django.contrib.auth import authenticate, login as auth_login
from django.template import RequestContext
from .models import NewUser, AdminLogin
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
        password = request.POST.get('password')
        
        url = 'http://127.0.0.1:8000/api/login/'
        data = {'username': username, 'password': password}
        
        try:
            response = requests.post(url, data=data)
            # response.raise_for_status()  # Raise an HTTPError for bad responses
            response_data = response.json()
            print(response_data)
        except requests.exceptions.RequestException as e:
            context = {
                'errors': f'Error occurred: {e}'
            }
            return render(request, 'admin_login.html', context)
        
        if response.status_code == 200:
            return redirect('dashboard')
        else:
            context = {
                'error': response_data.get('user_error', response_data.get('pass_error', response_data.get('error', 'Invalid credentials')))
            }
            return render(request, 'admin_login.html', context)
    
    return render(request, 'admin_login.html')


@login_required
def logout(request):
    user = request.user
    token = Token.objects.get(user=user)
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

    # Clear the session and redirect to the login page
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


def user_module_view(request): 
    if request.method == 'POST':
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        contact = request.POST.get("contact", "").strip()
        designation = request.POST.get("designation", "").strip()
        password = request.POST.get("password", "").strip()
        cpassword = request.POST.get("cpassword", "").strip()
        
        # Get checkbox values
        permissions = {
            "enquiry": "Enquiry" in request.POST,
            "enrollment": "Enrollment" in request.POST,
            "attendance": "Attendance" in request.POST,
            "staff": "Staff" in request.POST,
            "placement": "Placement" in request.POST,
            "report": "Report" in request.POST,
        }

        if password == cpassword:
            newuser = NewUser(
                name=username,
                email=email,
                contact=contact,
                designation=designation,
                password=password,
                enquiry=permissions["enquiry"],
                enrollment=permissions["enrollment"],
                attendance=permissions["attendance"],
                staff=permissions["staff"],
                placement=permissions["placement"],
                report=permissions["report"],
            )
            
            newuser.save()
            return redirect('manage-user')
    
    return render(request, 'new_user.html')


def manage_user_view(request):
    # Fetch all users or the relevant queryset
    users_list = NewUser.objects.all().order_by('-id')
    
    # Get the per_page value from the request, default to 10 if not provided
    per_page = request.GET.get('per_page', '10')

    # Apply pagination
    paginator = Paginator(users_list, per_page)  # Show per_page users per page
    
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'per_page': per_page,
    }
    return render(request, 'manage_user.html', context)

# create APIS

# user login api
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
    
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = authenticate(username=serializer.validated_data['username'], password=serializer.validated_data['password'])
        token, _ = Token.objects.get_or_create(user=user)
        return Response({'token': token.key}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# user logout view
@api_view(["POST",])
@permission_classes([IsAuthenticated])
def user_logout(request):
    if request.method == "POST":
        request.user.auth_token.delete()
        return Response({"Message": "You are logged out"}, status=status.HTTP_200_OK)
