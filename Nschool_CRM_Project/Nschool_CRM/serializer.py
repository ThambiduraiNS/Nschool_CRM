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
    class Meta:
        model = Enquiry
        fields = '__all__'

class NotesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notes
        fields = '__all__'
        
class EnrollmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Enrollment
        fields = '__all__'

class InstallmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Installment
        fields = '__all__'

class SinglePaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = SinglePayment
        fields = '__all__'
        
class BaseEMISerializer(serializers.ModelSerializer):
    class Meta:
        model = EMI_1  # You can use any EMI model since all are the same structure
        fields = '__all__'

class EMI_1_Serializer(BaseEMISerializer):
    class Meta(BaseEMISerializer.Meta):
        model = EMI_1

class EMI_2_Serializer(BaseEMISerializer):
    class Meta(BaseEMISerializer.Meta):
        model = EMI_2

class EMI_3_Serializer(BaseEMISerializer):
    class Meta(BaseEMISerializer.Meta):
        model = EMI_3

class EMI_4_Serializer(BaseEMISerializer):
    class Meta(BaseEMISerializer.Meta):
        model = EMI_4

class EMI_5_Serializer(BaseEMISerializer):
    class Meta(BaseEMISerializer.Meta):
        model = EMI_5

class EMI_6_Serializer(BaseEMISerializer):
    class Meta(BaseEMISerializer.Meta):
        model = EMI_6
        

class PaymentInfoSerializer(serializers.ModelSerializer):
    single_payment = SinglePaymentSerializer(read_only=True)
    # installments = InstallmentSerializer(many=True, read_only=True)
    emi_1_payments = EMI_1_Serializer(many=True, read_only=True)  # Assuming it's a related field
    emi_2_payments = EMI_2_Serializer(many=True, read_only=True)
    emi_3_payments = EMI_3_Serializer(many=True, read_only=True)
    emi_4_payments = EMI_4_Serializer(many=True, read_only=True)
    emi_5_payments = EMI_5_Serializer(many=True, read_only=True)
    emi_6_payments = EMI_6_Serializer(many=True, read_only=True)
    
    class Meta:
        model = PaymentInfo
        fields = '__all__'