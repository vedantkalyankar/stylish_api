import os
import logging
from django.core.files.uploadedfile import InMemoryUploadedFile, UploadedFile
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from authentication.core.jwt_utils import TokenManager
from authentication.serializers import UserSerializer

logger = logging.getLogger(__name__)

class ProfileService:
    """Service class to handle user profile operations"""

    @staticmethod
    def get_profile(user):
        """Get user profile
        Args:
            user: User object
        Returns: 
            dict: serialized user data

        """
        serializer = UserSerializer(user)
        return serializer.data
    
    @staticmethod
    def update_profile(user, data, files=None):
        """Update user profile data
        
        Args:
            user(): User object
            data(dict): Updated profile data 
            file(dict, optional): files from the request. Defaults to None.
            
        Returns:
            tuple(success, response_dict, status_code):"""
        try:
            # Handle profile picture file if provided
            if files and 'profile_picture' in files:
                success = ProfileService._process_profile_picture_file(user, files['profile_picture'])
                if not success:
                    return False, {
                        "success": False,
                        "error" : "Failed to process profile picture"
                    }, 400
                
            # Handle password change if provided 
            if 'current_password' in data and 'new_password' in data:
                result = ProfileService._process_password_change(user, data.get('current_password'),data.get('new_password'))

                if not result['success']:
                    return False, {
                        "success" : False,
                        "error": result['error']
                    }, 400
            # Remove processed fields before passing to serializer
            safe_data = {k:v for k, v in data.items() if k not in['profile_picture','current_password', 'new_password']}

            # update through serializer
            serializer = UserSerializer(user,data = safe_data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return True, {
                    "success": True,
                    "data": serializer.data,
                    "message": "Profile updated successfully"
                }, 200
            return False, {
                "success": False,
                "error": serializer.errors
            }
        except Exception as e:
            logger.error(f"profile update error:{str(e)}")
            return False, {
                "success": False,
                "error": "Failed to update profile"
            }, 500

    @staticmethod
    def _process_password_change(user, current_password, new_password):
        """process password change request
        
        Args:
            user: user object
            current_password (str): current user password
            new_password(str): New password to set
            
        Returns:
            dict: result with success flag and error message if applicable
        """

        # Verify current password
        if not user.check_password(current_password):
            return {'success': False, 'error': 'Current password is incorrect'}
        
        # Validate new password 
        try:
            validate_password(new_password, user=user)
        except ValidationError as e:
            return {'success' : False, 'error' : ', '.join(e.messages)}
        
        # update password
        user.set_password(new_password)
        user.save(update_fields= ['password'])

        # Log password change for security 
        logger.info(f"Password changed for user {user.id}")

        # Invalidate all existing refresh tokens for security
        TokenManager.blacklist_all_user_tokens(user.id)
        return {'success': True}
    @staticmethod
    def _process_profile_picture_file(user, file):
        """Process uploded picture file
        
        Args:
         user():User object
         file(): uploaded file object (InMemoryUploadedFile or UploadedFile)
        Returns:
            bool: success status
         """
        try:
            # Validate file type
            if not ProfileService._is_valid_image_file(file):
                logger.error(f"Invalid image fiel type: {file.content_type}")
                return False
            
            # Validate file size (e.g. max size)
            max_size = 5* 1024*1024 
            if file.size > max_size:
                logger.error(f"File too large: {file.size}bytes")
                return False
            
            # Handle existing profile picture
            if user.profile_picture:
                try:
                    if os.path.isfile(user.profile_picture.path):
                        os.remove(user.profile_picture.path)
                        logger.info(f"Removved old profile picture: {user.profile_picture.path}")
                except Exception as e:
                    logger.warning(f"Could not remove old profile picture. {str(e)}")
            # set new profile picture
            user.profile_picture = file
            user.save(update_fields = ['profile_picture'])
            logger.info(f"Profile picture is updated for user{user.id}")
            return True
        
        except Exception as e:
            logger.error(f"Error processing profile picture {str(e)}")
            return False
        


    @staticmethod
    def _is_valid_image_file(file):
        """Validate uploaded image file
        
        Args:
            file(): Uploaded file object
            
        Returns:
            bool: True if it is valid image file    
        """
        if not isinstance(file,(InMemoryUploadedFile, UploadedFile)):
            return False
        
        # Check content type
        valid_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp']

        if file.content_type not in valid_types:
            return False
        
        # check file extension
        valid_extensions = ['.jpg','.png','gif', '.webp', '.jpeg']
        file_ext = os.path.splitext(file.name)[1].lower()
        if file_ext not in valid_extensions:
            return False