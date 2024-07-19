from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate
from .models import *

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
            # email=validated_data['email']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    
    def validate(self, data):
        user = authenticate(username=data['username'], password=data['password'])
        if user:
            return data
        raise serializers.ValidationError('Invalid credentials')

class NewUserSerializer(serializers.Serializer):
    class Meta:
        model = NewUser
        fields = '__all__'