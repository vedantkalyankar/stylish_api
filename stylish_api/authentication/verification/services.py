import logging
import threading
import traceback
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .emails import EmailService
from .tokens import TokenVerifier

User = get_user_model()
logger = logging.getLogger(__name__)

class EmailVerificationService:
    """Service class to handle email verification operations"""

    @staticmethod
    def get_verification_cache_key(user_id):
        """Get standardized cache key for user verification status"""
        return f"user_verified_status_{user_id}"
    
    @staticmethod
    def send_verification_email(user):
        """
        Send Verification email to user
        
        Args:
            user: User object
        Returns:
            tuple: (success, response_dict, status_code)
            
        """
        try:
            if user is None:
                return False, {
                    "success": False,
                    "error": "Invalid user"
                }, 400

            if getattr(user, "is_verified", False):
                return True, {
                    "success": True,
                    "message": "Email is already verified"
                }, 200
            
            # Rate limiting per user
            rate_key = f"verification_email_{user.pk}"
            if cache.get(rate_key):
                # get timeout remaining(in sec)
                timeout_value = 300
                return False, {
                    "success": False,
                    "error": "please wait before requesting another verification email.",
                    "retry_after": timeout_value
                }, 429

            # Queue verification email to be sent in background
            try:
                threading.Thread(
                    target=EmailVerificationService.send_verification_email_background,
                    args=(user.pk,),
                    daemon=True
                ).start()
                cache.set(rate_key, True, timeout=300)
                logger.info(f"Verification email queued for {user.email}")
                return True, {
                    "success": True,
                    "message": "Verification email sent successfully. Please check your inbox."
                }, 200
            except Exception as thread_error:
                logger.error(f"Failed to queue verification email thread: {str(thread_error)}")
                return False, {
                    "success": False,
                    "error": "Failed to send verification email. Please try again later."
                }, 500
            
        except Exception as e:
            logger.error(f"Send verification email error: {str(e)}")
            return False, {
                "success": False,
                "error": "Failed to send verification email. Please try again later"
            }, 400

    @staticmethod
    def verify_email(uid64, token):
        """
        Verify email with token 

        Args:
            uid64 (str) : Base64 encoded user ID
            token (str) : verification token

        Returns:
            tuple: (success, response_dict, status_code)
        """
        is_valid, user, error = TokenVerifier.verify_token(uid64, token)

        if not is_valid:
            logger.warning(f"Invalid token verification attempt with uid64: {uid64}")
            return False, {
                "success": False,
                "error": error or "Invalid verification link. Please request a new one"
            }, 400

        if user is None:
            logger.error(f"Token verifier returned no user for uid64: {uid64}")
            return False, {
                "success": False,
                "error": "Invalid verification link. Please request a new one"
            }, 400
        
        try:
            from django.db import transaction
            with transaction.atomic():
                if not getattr(user, "is_verified", False):
                    if not hasattr(user, "is_verified"):
                        logger.error(f"User model missing is_verified field: {user}")
                        return False, {
                            "success": False,
                            "error": "Email verification field not configured"
                        }, 500

                    setattr(user, "is_verified", True)
                    user.save(update_fields=["is_verified"])
                    logger.info(f"Email verified for user {user.pk} ({user.email}) via link")
                else:
                    logger.info(f"Email verification attempt for already verified user: {user.pk} ({user.email})")

            cache_key = EmailVerificationService.get_verification_cache_key(user.pk)
            cache.set(cache_key, True, timeout=3600)
            logger.info(f"Updated verification cache for user {user.pk} : set to True")
            return True, {
                "success": True,
                "message": "Email verification successful."
            }, 200
        except Exception as e:
            logger.error(f"Error during email verification: {str(e)}")
            return False, {
                "success": False,
                "error": "An error occured during verification. Please try again"
            }, 500

    @staticmethod
    def send_verification_email_background(user_id):
        """Background method for sending verification emails
        
        Args:
            user_id: User ID"""
        
        try:
            email_service = EmailService()
            send_retry = getattr(email_service, "send_verification_email_with_retry", None)
            if callable(send_retry):
                send_retry(user_id, 3)
            else:
                raise AttributeError("EmailService missing send_verification_email_with_retry")
            logger.info(f"Background verification email queued for user ID {user_id}")
        except Exception as e:
            logger.error(f"Failed to send background verification email: {str(e)}")
            logger.error(traceback.format_exc())

    @staticmethod
    def check_verification_status(user):
        """
        Check email verification status
        Args:
            user: User Object
        Returns:
            tuple: (success, response_dict, status_code)
        """

        try:
            cache_key = EmailVerificationService.get_verification_cache_key(user.pk)
            cached_status = cache.get(cache_key)

            if cached_status is not None:
                logger.info(f"using cached verification status for user {user.pk}: {cached_status}")
                return True, {
                    "success": True,
                    "data": {"is_verified": cached_status}
                }, 200
            
            try:
                fresh_user = User.objects.get(pk=user.pk)
                if not hasattr(fresh_user, "is_verified"):
                    logger.error(f"User model missing is_verified field for user {user.pk}")
                    return False, {
                        "success": False,
                        "error": "User verification field not found"
                    }, 500

                is_verified = getattr(fresh_user, "is_verified", False)
                cache.set(cache_key, is_verified, timeout=3600)

                logger.info(f"Fetched verification status from DB for user {user.pk}: {is_verified}")
                return True, {
                    "success": True,
                    "data": {"is_verified": is_verified}
                }, 200
            except User.DoesNotExist:
                logger.error(f"User {user.pk} not found in database")
                return False, {
                    "success": False,
                    "error": "User not found"
                }, 404
        except Exception as e:
            logger.error(f"check verification status error: {str(e)}")
            return True, {
                "success": True,
                "data": {"is_verified": getattr(user, "is_verified", False)},
                "message": "could not check latest status, using existing information"
            }, 200
        
