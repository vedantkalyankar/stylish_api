import logging
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from authentication.serializers import UserSerializer
from  authentication.core.jwt_utils import TokenManager
from authentication.models import User
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)

class AuthenticationService:
    """Service class to handel authentication related business logic"""

    @staticmethod
    def register(email, password, phone_number = None, full_name = None, request_meta= None):
        """Handle user registration with email and password 
        Args:
        email(str):User email
        password(str): User password
        phone_numeber(str, optional): User's phone number.
        full_name(str, optional): Users' full name
        request_meta(dict, optional): Request metadata for security logging

        Returns:
            tuple:(success, response_dict, status_code)

        """
        from stylish_api.authentication.verification.services import EmailVerificationService
        if not email or not password:
            return False, {"success":False, "error":"Email and password are required"}, 400
        
        #log reqistration attempt
        if request_meta:
            logger.info(f"Registration attempt from IP: {request_meta.get('REMOTE_ADDR')}")

        try:
            # Check if email already exists
            if User.objects.filter(email=email).exists():
                return False,{
                    "success" : False,
                    "error": "A user with this email already exists"
                }, 400
            # validate password streangth
            try:
                validate_password(password)
            except ValidationError as e:
                return False,{
                    "success":False,
                    "error":", ".join(e.messages)
                }, 400
            # Create new user without relying on a custom manager helper
            user = User(
                email=email,
                is_verified=False  # Email verification needed
            )
            user.set_password(password)
            user.save()

            # Update additional fields if provided
            if full_name:
                name_parts = full_name.strip().split()
                if len(name_parts) == 1:
                    user.first_name = name_parts[0]
                    user.last_name = ''
                else:
                    user.first_name = name_parts[0]
                    user.last_name = ' '.join(name_parts[1:])
                user.save(update_fields=['first_name', 'last_name'])

            if phone_number:
                user.phone_number = phone_number
                user.save(update_fields=['phone_number'])

            # Queue verification email for users asynchronously
            if user.email and settings.REQUIRED_EMAIL_VERIFICATION:
                # Use cache to mark that verification email should be sent
                cache_key = f"queue_verification_email_{user.pk}"
                cache.set(cache_key, True, timeout=3600)
                # 1 hour queue validity
                # Trigger an asynchronous task for email.
                try:
                    # Forward to EmailVerificationService for sending Email
                    EmailVerificationService.send_verification_email_background(user.pk)
                    logger.info(f"Queued verification email for user: {user.email}")

                except Exception as thread_error:
                    # Log but don't fail registration if email queueing fails
                    logger.error(f"Failed to queue verification email: {str(thread_error)}")

            # serialize user data
            serializer = UserSerializer(user)

            # Generate tokens
            tokens = TokenManager.generate_tokens(user)

            # Log sucessful registration 
            logger.info(f"Registration successful for user : {user.email}")

            # Return successful response data
            return True, {
                "success" : True,
                "data" : {
                    "user" : serializer.data,
                    "tokens" : tokens,
                    "is_new_user" : True,
                    "email_verified" : user.is_verified
                }
            }, 201
        
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            return False,
        {
                "success" : False,
                "error" : "Registration failed. Please try again",
        }, 400

    @staticmethod
    def login(email, password, device_info=None, request_meta=None):
        """
        Handle User logiin with email and password

        Args:
        email (str) : User email
        password (str) : User password
        device_info (dict, optional) : Device information for audit
        request_meta(dict, optional) :Request metadata for security logging

        Returns :
            tuple : (success, response_dict, status_code)
        """

        if not email or not password:
            return False, {
                "success" : False,
                "error" : "Email ans password are required"
            }, 400
        
        # Log Login attempt with seurity metadata
        if request_meta:
            logger.info(f"Login attempt from IP :{request_meta.get('REMOTE_ADDR')} User-Agent :{request_meta.get('HTTP_USER_AGENT')}")

        try:
            # check for account lockout
            if cache.get(f"account_lockout:{email}"):
                logger.warning(f"Login attempt for locked account: {email}")
                return False,{
                    "success" : False,
                    "error": "Account temperorily locked due to multiple failed attempts. Try again later",
                    "lockout": True
                }, 403
            # Authenticate with django's system
            user = authenticate(username = email, password = password)

            # if authentication failed
            if not user:
                # Increment failed login attempts
                failed_attempts = cache.get(f"failed_logins:{email}", 0)+ 1
                cache.set(f"failed_logins: {email}",failed_attempts, timeout=1800)

                # Lock account after 5 failed attempts
                if failed_attempts >= 5:
                    cache.set(f"account_lockout:{email}", True, timeout=900)
                    logger.warning(f"Account Locked due to failed Attempts: {email}")
                    return False,{
                        "success" : False,
                        "error" : "Account temprorily locked due to multiple failed attempts. Try again later.",
                        "Lockout" : True
                    }, 403
                
                logger.warning(f"Failed login attempt for email: {email}")
                return False, {
                    "success" : False,
                    "error" : "Invalid Email or Password"
                }, 401
            
            if not user.is_active:
                logger.warning(f"Login attempt for disable account: {email}")
                return False, {
                    "success" : False,
                    "error" : "Account is disabled. Please contact support."
                }, 403
            
            # Reset failed lgin attempts upon successful login
            cache.delete(f"failed_logins:{email}")

            # serialize user data
            serializer = UserSerializer(user)

            # Generate tokens
            tokens = TokenManager.generate_tokens(user)

            # Record login time upon successful login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])

            # Log successful login
            if request_meta:
                logger.info(f"Login successful for user: {user.email} from IP : {request_meta.get('REMOTE_ADDR')}")

            # Return successful response
            return True, {
                "data" :{
                    "user" : serializer.data,
                    "tokens" : tokens,
                    "email_verified": getattr(user, "is_verified", False),
                    "verification_needed": not getattr(user, "is_verified", False) and settings.REQUIRE_EMAIL_VERIFICATION
                }
            },200

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return False, {
                "success": False,
                "error" : "Authentication failed. Please try again."
                },401
        

    @staticmethod
    def refresh_token(refresh_token):
        """
        Refresh an authentication token
        Args:
            refresh_token (str): The refresh token to use

        Returns:
            tuple: (success, response_dict, status_code)
        """
        if not refresh_token:
            return False, {"success": False, "error": "Refresh token is required"}, 400

        try:
            # use token manager to refresh the token 
            tokens = TokenManager.refresh_tokens(refresh_token)

            # Check if tokens were successfully generated
            if not tokens:
                return False, {"success": False, "error": "Failed to refresh tokens"}, 400

            # Return successful response data
            return True,{
                "success": True,
                "data":{
                    'access_token': tokens['access_token'],
                    'refresh_token':tokens['refresh_token'],
                    'token_type': tokens['token_type'],
                    'expires_in':tokens['expires_in']
                }
            },200
        
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return False, {
                "success": False,
                "error": "An error occured during token refresh"
            },500
        
    def validate_token(self, token, user):
        """
        Validate a token and check if it belongs to the user
        Args:
            token (str): The token to validate
            user: The user object to check against

        Returns:
            tuple: (sucess, response_dict, status_code)
        """

        is_valid, user_id, token_type = TokenManager.validate_token(token)
        if not is_valid or user_id != user.id:
            logger.warning(f"Token validation failed: expected user{user.id}, got {user_id}")
            return False,{
                "success":False,
                "error": "Token validation failed"
            }
        # Access verification status through the service layer with cache handling
        from authentication.verification.services import EmailVerificationService
        success, verification_response, _ = EmailVerificationService.check_verification_status(user) 

        if not success:
            logger.error(f"Error checking verification status {user.id}")
            # Fall back to provided user object
            is_verified = user.is_verified
        else:
            is_verified = verification_response.get('data', {}).get('is_verified', user.is_verified)

        logger.info(f"Token validation retrived varification status for user {user.id} : is_verified={is_verified}")

        return True,{
            "success" : True,
            "data" : {
                'valid': True,
                'user_id': user_id,
                'email_verified': is_verified
            }
        }, 200
    
    @staticmethod
    def logout(user, refresh_token):
        """
        Handle user logout, invalidating tokens as needed

        Args:
            user: The user object logging out
            refresh_token (str, optional) : The refresh token t invalidate
        Returns:
            tuple: (success, response_dict, status_code)
        """

        # Invalidate specific token if provided
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                jti = token.get('jti')
                if jti:
                    TokenManager.blacklist_token(jti)
                    logger.info(f"Token blacklisted during logout: {jti}")

            except Exception as e:
                logger.warning(f"Error blacklisting token during logout:{str(e)}")

        # Log the logout event
        logger.info(f"User logged out: {user.id}")

        return True,{
            "success" : True,
            "message": "sucessfully logged out"
        }, 200
