import random
from account.models import User
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from account.serializers import UserRegistrationSerializer,UserLoginSerializer,UserProfileSerializer,UserChangePasswordSerializer,SendPasswordResetEmailSerializer, UserPasswordResetSerializer, LoginOtpSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from account.renderers import UserRenderer
from django.core.mail import send_mail
import os


#Generate Token Manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request):
       serializer = UserRegistrationSerializer(data=request.data)
       if serializer.is_valid(raise_exception=True):
           user = serializer.save()
           return Response({"message":"Successful Registration"},status=status.HTTP_201_CREATED)
       return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            token = get_tokens_for_user(user)
            return Response({"token": token, "message": "Successful Login"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated] 
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={"user": request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': "Password Changed Successfully"}, status = status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class SendLoginOtpView(APIView):
    def post(self, request):
        email = request.data.get('email')

        # Check if the email exists in the database
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "Email does not exist."}, status=status.HTTP_404_NOT_FOUND)

        # Generate OTP
        otp = random.randint(100000, 999999)

        # Save OTP and token in 
        user.otp = otp
        user.save()
        print("otp: ",otp)

        # Send OTP to the user's email
        subject = 'OTP for Registration'
        message = f'Your OTP is: {otp}'
        from_email = os.environ.get("EMAIL_HOST_USER")
        recipient_list = [email]
        send_mail(subject, message, from_email, recipient_list)

        return Response({"message": "OTP sent successfully."}, status=status.HTTP_200_OK)
    
class OTPLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):
        serializer = LoginOtpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token = get_tokens_for_user(user)
        user.otp = None
        user.save()
        return Response({"token": token, "message": "Successful Login"}, status=status.HTTP_200_OK)

    
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated] 
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(data=request.data, context={"user": request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': "Password Changed Successfully"}, status = status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
    
class SendPasswordResetEmailView(APIView):
    renderer_classes = {UserRenderer}
    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({"message": 'Password Reset Email sent. Please check your Email'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={"uid":uid, "token": token})
        if serializer.is_valid(raise_exception=True):
            return Response({"message": "Password Reset Successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST )
