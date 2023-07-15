# djangoauthapi
-> pull the repo into a folder named "djangoauthapi"
-> some postman endpoints like "User Profile" require you to put the token (user gets after login) in the header while hitting the User Profile view.

-> Features:
---> User Registeration(email, username, password, confirm passsword)
--->User Login(gets authenticated based on email or username and provides a token in return)
--->User Profile(gets the user details of the respective generated token, when sent in the header as 'bearer')
--->Password Change (change password while sending token in header)
--->Password Reset via Email(send a password reset token through email and validate the token when received in the UserPasswordResetView )
--->Login via Otp sent on email(firstly enter email in SendPasswordResetEmailView and then provide email and the otp in UserPasswordResetView )
-> Please create a .env file (it is gitignored in this project) with email configuration for email functionality.
-> Check the README file for further instructions and requirements.
-> Postman endpoints are added in the project files.


