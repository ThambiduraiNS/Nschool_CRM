from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate, get_user_model
from .models import *

# class LoginSerializer(serializers.Serializer):
#     username_or_email = serializers.CharField()
#     password = serializers.CharField()

#     def validate(self, data):
#         username_or_email = data.get('username_or_email')
#         password = data.get('password')
        
#         # Check if username_or_email is an email or username
#         user = None
#         if '@' in username_or_email:
#             user = authenticate(email=username_or_email, password=password)
#         else:
#             user = authenticate(username=username_or_email, password=password)
        
#         if user is None:
#             raise serializers.ValidationError('Invalid credentials')
        
#         return data


# User = get_user_model()

# class UserSerializer(serializers.ModelSerializer):
    
#     username = serializers.CharField(required=True)
#     password = serializers.CharField(required=True, write_only=True)
    
#     class Meta:
#         model = AdminLogin
#         fields = ['id', 'username', 'password']
#         extra_kwargs = {
#             'password': {'write_only': True}
#         }

#     def create(self, validated_data):
#         user = AdminLogin(
#             username=validated_data['username'],
#             # email=validated_data['email']
#         )
#         user.set_password(validated_data['password'])
#         user.save()
#         return user
    
#     def validate(self, data):
#         user = authenticate(username=data['username'], password=data['password'])
#         if user:
#             return data
#         raise serializers.ValidationError('Invalid credentials')

# User = get_user_model()

class LoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        username = data.get('username_or_email')
        password = data.get('password')

        if username and password:
            return data
        else:
            raise serializers.ValidationError("Must include 'username' and 'password'")

class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    
    class Meta:
        model = AdminLogin
        fields = ['id', 'username', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        user = AdminLogin(
            username=validated_data['username'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class NewUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewUser
        fields = '__all__'
        
class NewUserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewUser
        exclude = ['password',]
        