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

class NewUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewUser
        fields = '__all__'
        
class NewUserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewUser
        exclude = ['password',]
        
class CourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = '__all__'
        
class EnquiryModeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Enquiry_Mode
        fields = '__all__'
        
class EnquirySerializer(serializers.ModelSerializer):
    # course_name = serializers.CharField(source='course_name.course_name', read_only=True)
    class Meta:
        model = Enquiry
        fields = '__all__'