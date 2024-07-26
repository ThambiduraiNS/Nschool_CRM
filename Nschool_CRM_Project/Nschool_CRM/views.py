import json, requests
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
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

def user_module_view(request):
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

        # Prepare data for the API request
        user_data = {
            'name': username,
            'email': email,
            'contact': contact,
            'designation': designation,
            'password': password,
            'enquiry': "Enquiry" in request.POST,
            'enrollment': "Enrollment" in request.POST,
            'attendance': "Attendance" in request.POST,
            'staff': "Staff" in request.POST,
            'placement': "Placement" in request.POST,
            'report': "Report" in request.POST,
        }

        # Get the token
        try:
            token = Token.objects.get()
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
            return redirect('manage-user')
        else:
            context = {
                'name': response_data.get('name', ''),
                'email': response_data.get('email', ''),
                'contact': response_data.get('contact', ''),
                'designation': response_data.get('designation', ''),
                'password': response_data.get('password', ''),
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

def manage_user_view(request):
    # Fetch the token
    try:
        token = Token.objects.get()  # Assuming you only have one token and it's safe to get the first one
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
            'name': request.POST.get('username', user.name),
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
                'name': response_data.get('name', ''),
                'email': response_data.get('email', ''),
                'contact': response_data.get('contact', ''),
                'designation': response_data.get('designation', ''),
            }
            return render(request, 'update_user.html', context)
        
    return render(request, 'update_user.html', {"user": user})
    
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