import json
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate
from django.contrib.auth import authenticate, login
from django.template import RequestContext
from .models import NewUser

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
            
            return redirect('dashboard')  # Replace with your success URL
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
    return render(request, 'new_user.html')

def manage_user_view(request):
    return render(request, 'manage_user.html')

class UserListCreate(generics.ListCreateAPIView):
    queryset = NewUser.objects.all()
    serializer_class = NewUserSerializer
    permission_classes = [IsAuthenticated] 

class UserDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = NewUser.objects.all()
    serializer_class = NewUserSerializer
    permission_classes = [IsAuthenticated] 
