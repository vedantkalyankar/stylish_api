import logging 
import traceback
import time
import random
import string
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model


User = get_user_model()
logger = logging.getLogger(__name__)

class EmailService:
    """Service for sending user verification emails"""

    @staticmethod
    def send_verification_email(user):
        """Send verification email to user with both link and code
        Args:
            user: user object
        Returns: 
            bool: Success status
        """
        try:
            # Generate verification token for link
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Create verification link
            verify_url = f"{settings.FRONTEND_URL}/auth/email-verifiy?utid={uid}&token={token}"

            # compose email
            subject = f"{settings.APP_NAME} - Verify your email address"

            # Templete context
            context = {
                'user' : user,
                'verify_url' : verify_url,
                'app_name' : settings.APP_NAME,
                'code_expiry' : '1 hour'
            }
            try:
                # HTML message
                html_message = render_to_string('emails/verify_email.html', context)

                # Plain text fallback - create a simple text version
                plain_message = f"""Hello {user.email},
                Please verify your email address by clicking the link below:

                {verify_url}
                Thank you,
                {settings.APP_NAME} Team
                """
            except Exception as templete_error:
                # Fallback to plain text email if templete rendering fails
                logger.error(f"Templete rendering error: {str(templete_error)}")
                html_message = None
                plain_message = f"""
                Hello {user.email},

                Please verify your email adderss by clicking the link below:

                {verify_url}

                Thank you,
                {settings.APP_NAME} Team
                """
         # verify SMTP settings before sending email
            try:
                # Check if EMAIL_HOST_USER and EMAIL_HOST_PASSWORD are set
                if not settings.EMAIL_HOST_USER or not settings.EMAIL_HOST_PASSWORD:
                    logger.error(f"Email credentials are not configured properly in the settings.")
                    return False
                from_email = settings.DEFAULT_FROM_EMAIL or settings.EMAIL_HOST_USER
                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False
                    )

                logger.info(f"verification email send to {user.email}")
                return True
            except Exception as e:
                logger.error(f"SMTP error sending verification email:{str(e)}")
                logger.error(traceback.format_exc())
                return False
            
        except Exception as e: 
            logger.error(f"Error in verification email prepration:{str(e)}")
            logger.error(traceback.format_exc())
            return False
                
    @staticmethod
    def send_varification_email_with_retry(user_id, max_attempts=3):
        try:
            # Get user by ID
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            logger.error(f"Background verification email: USer {user_id} not found")
            return
        # Check if already verified
        if getattr(user, 'is_verified', False):
            logger.info(f"Background verification : User {user.email} already verified")
            return
        
        # make multiple attempts with backoff
        for attempt in range(1, max_attempts+1):
            try:
                success = EmailService.send_verification_email(user)
                if success:
                    logger.info(f"Background verification email sent to {user.email} on attempt {attempt}")
                    return
                else:
                    logger.error(f"Failed to send verification email on attempt {attempt}")

            except Exception as e:
                logger.error(f"Error in background Verification email attempt {attempt} : {str(e)}")

            # Exponential backoff between attempts
            if attempt < max_attempts:
                time.sleep(2 ** attempt)
            
        logger.error(f"Failed to send verification email after {max_attempts} attempts")

    @staticmethod
    def send_password_reset_email(user):
        """send password rest email to user with both link
        
        Args:
            user(str) : User object
            
        Return:
            tuple:(bool, reset_code) - Success status
             
     """
        try:
            # Generate verification token for link
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Create verification link
            reset_url = f"{settings.FRONTEND_URL}/auth/password-reset-confirm?utid={uid}&token={token}"

            # compose email
            subject = f"{settings.APP_NAME} - Reset your password"

            # Templete context
            context = {
                'user' : user,
                'verify_url' : reset_url,
                'app_name' : settings.APP_NAME,
                'code_expiry' : '1 hour'
            }
            try:
                # HTML message
                html_message = render_to_string('emails/password_reset.html', context)

                # Plain text fallback - create a simple text version
                plain_message = f"""Hello {user.email},
                You requested to restart your password for your{settings.APP_NAME} account.
                Please click the link below to reset rour password:

                {reset_url}
                If you didn't request this , please ignore this email
                Thank you,
                {settings.APP_NAME} Team
                """
            except Exception as templete_error:
                # Fallback to plain text email if templete rendering fails
                logger.error(f"Templete rendering error: {str(templete_error)}")
                html_message = None
                plain_message = f"""
                Hello {user.email},

                Please verify your email adderss by clicking the link below:

                {reset_url}

                Thank you,
                {settings.APP_NAME} Team
                """
         # verify SMTP settings before sending email
            try:
                # Check if EMAIL_HOST_USER and EMAIL_HOST_PASSWORD are set
                if not settings.EMAIL_HOST_USER or not settings.EMAIL_HOST_PASSWORD:
                    logger.error(f"Email credentials are not configured properly in the settings.")
                    return False
                from_email = settings.DEFAULT_FROM_EMAIL or settings.EMAIL_HOST_USER
                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False
                    )

                logger.info(f"password email send to {user.email}")
                return True
            except Exception as e:
                logger.error(f"Error sending password reset email:{str(e)}")
                logger.error(traceback.format_exc())
                return False
            
        except Exception as e: 
            logger.error(f"Error in verification email prepration:{str(e)}")
            logger.error(traceback.format_exc())
            return False