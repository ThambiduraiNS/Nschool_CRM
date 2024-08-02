from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth import authenticate, get_user_model
from .models import *

class LoginSerializer(serializers.Serializer):
    # username_or_email = serializers.CharField()
    username_or_email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        username_or_email = data.get('username_or_email')
        password = data.get('password')

        if '@' in username_or_email:
            user = authenticate(request=self.context.get('request'), email=username_or_email, password=password)
        else:
            user = authenticate(request=self.context.get('request'), username=username_or_email, password=password)

        if user is None:
            raise serializers.ValidationError('Invalid credentials')

        data['user'] = user
        return data


class UserSerializer(serializers.ModelSerializer):
    
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    
    class Meta:
        model = NewUser
        fields = ['id', 'username', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        user = NewUser(
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

class NewUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewUser
        fields = '__all__'
        
class NewUserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewUser
        exclude = ['password',]
        