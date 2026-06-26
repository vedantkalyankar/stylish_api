import logging
import traceback

from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

from authentication.core.base_view import BaseAPIView
from authentication.verification.tokens import TokenVerifier
from authentication.core.jwt_utils import TokenManager
from ..core.response import standardized_response
from .password_reset_service import PasswordResetService
from .services import EmailVerificationService, User

logger = logging.getLogger(__name__)


class VerifyEmailView(BaseAPIView):
    """Endpoint for verifying email with token."""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        try:
            # Use query parameters or POST data (for flexibility)
            uid64 = request.data.get("uid") or request.query_params.get("uid")
            token = request.data.get("token") or request.query_params.get("token")

            if not uid64 or not token:
                return Response(
                    standardized_response(
                        success=False,
                        error="Missing required fields",
                    ),
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Use service layer for email verification
            _, response_data, status_code = EmailVerificationService.verify_email(
                uid64=uid64,
                token=token,
            )

            return Response(
                standardized_response(**response_data),
                status=status_code,
            )

        except Exception as e:
            logger.error(f"Email verification error: {str(e)}")
            logger.error(traceback.format_exc())

            return Response(
                standardized_response(
                    success=False,
                    error="Email verification failed. Please try again.",
                ),
                status=status.HTTP_400_BAD_REQUEST,
            )

    # GET method for direct verification from email links
    def get(self, request):
        # Forward to POST method for consistent handling
        return self.post(request)


class SendVerificationEmailView(BaseAPIView):
    """Endpoint for sending verification email."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def post(self, request):
        try:
            # Use service layer for sending verification email
            _, response_data, status_code = (
                EmailVerificationService.send_verification_email(request.user)
            )

            return Response(
                standardized_response(**response_data),
                status=status_code,
            )

        except Exception as e:
            logger.error(f"Send verification email error: {str(e)}")
            logger.error(traceback.format_exc())

            return Response(
                standardized_response(
                    success=False,
                    error="Failed to send verification email. Please try again later.",
                ),
                status=status.HTTP_400_BAD_REQUEST,
            )


class CheckVerificationStatusView(BaseAPIView):
    """Endpoint for checking verification status."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self, request):
        try:
            _, response_data, status_code = (
                EmailVerificationService.check_verification_status(request.user)
            )

            logger.info(
                f"Verification status check for user {request.user.pk}: "
                f"{response_data.get('data', {}).get('is_verified')}"
            )

            return Response(
                standardized_response(**response_data),
                status=status_code,
            )

        except Exception as e:
            logger.error(f"Check verification status error: {str(e)}")
            logger.error(traceback.format_exc())

            # Fall back to existing user information
            return Response(
                standardized_response(
                    success=True,
                    data={"is_verified": request.user.is_verified},
                    message="Could not check latest status, using existing information.",
                ),
                status=status.HTTP_200_OK,
            )


class PasswordResetView(BaseAPIView):
    """Endpoint for requesting password reset."""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        try:
            email = request.data.get("email")

            if not email:
                return Response(
                    standardized_response(
                        success=False,
                        error="Email is required",
                    ),
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Use service layer for password reset
            password_reset_service = PasswordResetService()
            _, response_data, status_code = password_reset_service.request_rest(
                email=email
            )

            return Response(
                standardized_response(**response_data),
                status=status_code,
            )

        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            logger.error(traceback.format_exc())

            return Response(
                standardized_response(
                    success=True,
                    message="If an account exists with this email, a password reset link will be sent.",
                ),
                status=status.HTTP_200_OK,
            )

    @staticmethod
    def confirm_reset(uid64, token, new_password):
        """Complete password reset with token and new password"""

        is_valid, user, error = TokenVerifier.verify_token(uid64, token)

        if not is_valid or user is None:
            return False, {
                "success": False,
                "error": error or "Invalid password reset link. please request a new one"
            }, 400

        try:
            validate_password(new_password, user=user)

        except ValidationError as e:
            return False, {
                "success": False,
                "error": ", ".join(e.messages)
            }, 400   # FIXED: missing status code

        user.set_password(new_password)
        user.save(update_fields=['password'])

        logger.info(f"Password reset completed for user {user.pk} via link")

        TokenManager.blacklist_all_user_tokens(user.pk)

        return True, {
            "success": True,
            "message": "Password has been successfully reset. You can now log in with your new password"
        }, 200
    
class ConfirmPasswordResetView(BaseAPIView):
    """
    Endpoint for confirming password reset using uid, token and new password.
    """

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    def post(self, request):
        try:
            uid64 = request.data.get("uid")
            token = request.data.get("token")
            new_password = request.data.get("new_password")

            if not uid64 or not token or not new_password:
                return Response(
                    standardized_response(
                        success=False,
                        error="uid, token and new_password are required",
                    ),
                    status=status.HTTP_400_BAD_REQUEST,
                )

            success, response_data, status_code = PasswordResetView.confirm_reset(
                uid64=uid64,
                token=token,
                new_password=new_password,
            )

            return Response(
                standardized_response(**response_data),
                status=status_code,
            )

        except Exception as e:
            logger.error(f"Confirm password reset error: {str(e)}")
            logger.error(traceback.format_exc())

            return Response(
                standardized_response(
                    success=False,
                    error="Password reset failed. Please try again.",
                ),
                status=status.HTTP_400_BAD_REQUEST,
            )

    def get(self, request):
        return self.post(request)