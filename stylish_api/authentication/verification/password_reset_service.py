import logging
import traceback
import threading
from .emails import EmailService
from  django.core.cache import cache 
from django.contrib.auth import get_user_model
from.tokens import TokenVerifier
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from authentication.core.jwt_utils import TokenManager

User = get_user_model()
logger = logging.getLogger(__name__)
class PasswordResetService:
    """Service class to handle password reset opeations"""
    @staticmethod
    def request_rest(email):
        """Request password reset for email
        Args:
            email (str): User email

        Returns:
            tuple: (success, response_dict, status_code)
        """

        try:
            if not email:
                return False, {
                    "success": False,
                    "error": "Email is required"
                }, 400
            
            # Rate limiting by email to prevent abuse
            rate_key = f"password_reset_{email}"
            if cache.get(rate_key):
                return True,{
                    "success": True,
                    "message":"If an account exists with this email, a password rest link will be sent."
                }, 200
            
            # Find user by email
            try:
                user = User.objects.get(email = email)

                # send email in background 
                threading.Thread(
                    target=EmailService.send_password_reset_email,
                    args=(user,),
                    daemon=True
                ).start()

            except User.DoesNotExist:
                pass

            # Rate linit regrdless of result (to prevent enumberation attacks)
            cache.set(rate_key, True, timeout=300)

            # for security, return success message regrdless of actual result
            return True, {
                "success": True,
                "message": "if an account exists with this email, a password reset will be sent."
            }, 200
        
        except Exception as e:
            logger.error(f"password reset error:{str(e)}")

            # for security, dont expose details
            return True,{
                "success": True,
                "message":"If an account exists with this email, a password reset link will be sent. "
            },200

    @staticmethod
    def confirm_reset(uid64, token, new_password):
        """Complete password with token and new passwrod
        "Args:"
            uid64 (str): Base64encoded userID
            token(type):Reset token
            new_password(str): New password

        Returns:
            tuple(success, response_dict, status_code)

        """

        is_valid, user, error = TokenVerifier.verify_token(uid64, token)

        if not is_valid or user is None:
            return False, {
                "success": False,
                "error": error or "Invalid password reset link. please request a new one"
            }, 400

        # Validate new password 
        try:
            validate_password(new_password, user=user)

        except ValidationError as e:
            return False, {
                "success": False,
                "error": ", ".join(e.messages)
            }
    
        # user password 
        user.set_password(new_password)
        user.save(update_fields=['password'])

        # Log password reset for security audit
        logger.info(f"Password reset completed for user {user.pk} via link")

        # Invalidate 
        TokenManager.blacklist_all_user_tokens(user.pk)

        return True, {
            "success" : True,
            "message" : "password has been successfully. You can now log in with your new password"
        }, 200