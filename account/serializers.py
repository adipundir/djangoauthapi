from xml.dom import ValidationErr
from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
import os

class UserRegistrationSerializer(serializers.ModelSerializer):
    #we need to add password2 field to confirm password
    password2 = serializers.CharField(style={'input_type':'password'},write_only=True)

    class Meta:
        model = User
        fields = ['email','username','password','password2']
        extra_kwargs = {
            'password':{'write_only':True}, 
        } 

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password didn't match")
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
        
class UserLoginSerializer(serializers.Serializer):
    username_or_email = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, attrs):
        username_or_email = attrs.get('username_or_email')
        password = attrs.get('password')

        # Check if the user exists with either username or email
        user = None
        if username_or_email:
            # Try to authenticate using the provided username or email
            user = authenticate(
                request=self.context.get('request'),
                username=username_or_email,
                password=password
            )
            if user is None:
                user = authenticate(
                    request=self.context.get('request'),
                    email=username_or_email,
                    password=password
                )

        # If user authentication fails, raise an error
        if not user:
            raise serializers.ValidationError('Invalid username/email or password.')

        # Attach the authenticated user to the serializer's context
        attrs['user'] = user
        return attrs

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User 
        fields = ['id','email','username']

class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style = {"input_type": "password"}, write_only = True)
    password2 = serializers.CharField(max_length = 255, style = {"input_type": "password"}, write_only = True)
    class Meta:
        fields = ['password', 'password2']   

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return attrs
    
class LoginOtpSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    otp = serializers.CharField(max_length=255)

    def validate(self, attrs):
        email = attrs.get('email')
        otp = attrs.get('otp')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            print("Email: ", email) 
            print("otp: ", otp)

            if user.otp != otp:
                raise serializers.ValidationError('Invalid OTP') 

            # Include the user object in the validated_data dictionary
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError("Invalid email")

        
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("Encoded UID: ", uid) 
            token = PasswordResetTokenGenerator().make_token(user)
            print("Token: ", token) 
            link = 'http://127.0.0.1:8000/api/users/reset/' +uid +'/' +token
            #send email
            body = "click the link to reset your password " +link
            data = {
                "subject": "Password Reset",
                "body": body,
                "to_email": user.email
            }
            send_mail(
                data["subject"],data["body"],os.environ.get("EMAIL_HOST_USER"),[data["to_email"]],fail_silently=False
            )
            return attrs
        else:
            raise ValidationErr('You are not a registered User') 

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 255, style = {"input_type": "password"}, write_only = True)
    password2 = serializers.CharField(max_length = 255, style = {"input_type": "password"}, write_only = True)
    class Meta:
        fields = ['password', 'password2']   

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password and confirm Password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                return ValidationErr("Token is not valid or expired")
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user,token)
            raise ValidationErr("Token is not valid or Expired")

 
      