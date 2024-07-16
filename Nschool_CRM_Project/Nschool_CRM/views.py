import json
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate
from django.contrib.auth import authenticate, login
from django.template import RequestContext
from .models import NewUser

from django.core.cache import cache
from django.core.paginator import Paginator

from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .serializer import NewUserSerializer

from rest_framework.authtoken.models import Token
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
# Create your views here.
@csrf_protect
def admin_login(request):
    if request.method == 'POST':
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "").strip()

        if not username or not password:
            context = {
                'error': 'Username and password are required.'
            }
            return render(request, 'admin_login.html', context)
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Create new token (deleting old token is optional, based on your use case)
            Token.objects.filter(user=user).delete()  # Optional: delete old token
            token, created = Token.objects.get_or_create(user=user)
            
            # Optionally store the token in the session or pass it to the next page
            request.session['auth_token'] = token.key  # Example of storing in session
            
            return redirect('dashboard') 
        else:
            context = {
                'error': 'Invalid credentials.'
            }
            return render(request, 'admin_login.html', context)
    
    return render(request, 'admin_login.html')


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
    print(request.POST)
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
    users_list = NewUser.objects.all()
    
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

class UserListCreate(generics.ListCreateAPIView):
    queryset = NewUser.objects.all()
    serializer_class = NewUserSerializer
    permission_classes = [IsAuthenticated] 

class UserDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = NewUser.objects.all()
    serializer_class = NewUserSerializer
    permission_classes = [IsAuthenticated] 
