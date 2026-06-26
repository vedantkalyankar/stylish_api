from tokenize import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
import jwt
import logging
import uuid
import time
from django.utils import timezone

logger = logging.getLogger(__name__)

class TokenManager:
    """Enhanced JWT Token manager with security features"""

    @staticmethod
    def generate_tokens(user):
        """Generate secure access and refresh tokens with enhanced clain=ms and security"""
        try:
            refresh = RefreshToken.for_user(user)
            # create unique JIT (JWT ID) fo better tracking 
            jti = str(uuid.uuid4())

            # Add custom claims with security considerations
            refresh['jti'] = jti
            refresh['username'] = user.username
            refresh['is_staff'] = user.is_staff
            refresh['is_verified'] = user.is_verified
            refresh['email'] = user.email
            refresh['type'] = 'refresh'

            # set up different claims for access token
            access_token = refresh.access_token
            access_token['type'] = 'access'
            access_token['jti'] = str(uuid.uuid4()) #Different JTI for access token
             
            # Get expiration times from settings
            access_expiry = settings.SIMPLE_JWT.get('ACCESS_TOKEN_LIFETIME', timedelta(minutes=15))
            refresh_expiry = settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME', timedelta(days=14))

            # store token metadata in cache fo potential revocation
            TokenManager._store_token_metadata(user.id, jti, refresh_expiry.total_seconds())

            # Return full token package
            return{
                'access_token': str(access_token),
                'refresh_token': str(refresh),
                'token_type': 'Bearer',
                'expires_in': int(access_expiry.total_seconds()),'user_id': user.id,
                'issued_at' : int(time.time()) 
            }
        
        except Exception as e:
            logger.error(f"Failed to generate tokens for user {user.id} : {str(e)}")
            raise
    
    @staticmethod
    def refresh_tokens(refresh_token):
        """Refresh tokens with validation and operational rotation"""
        try:
            # parse and validate the refresh token 
            token = RefreshToken(refresh_token)
            # check if token is blacklisted
            jti = token.get('jti')

            if not jti or TokenManager.is_token_blacklisted(jti):
                logger.warning(f"Attempt to use blacklisted token with JTI : {jti}")
                raise TokenError("Token is Blacklisted")
            # Get user from token
            user_id = token.get('user.id')
            from authentication.models import User # Import here to avoid circular imports

            try: 
                user = User.objects.get(id = user_id)
            except:
                logger.warning(f"Token refresh aattempted for non-existant user ID: {user_id}")
                raise TokenError("Invalid token")
            
            # Check if user is still active
            if not user.is_active:
                logger.warning(f"Token refresh attempted inactive user: {user.email}")
                # Blacklist the token
                TokenManager.blacklist_token(jti)
                raise TokenError("User is Inactive")
            # if token is enabled, blacklist the current token
            if settings.SIMPLE_JWT.get("ROTATE_REFRESH_TOKENS",True):
                TokenManager.blacklist_token(jti)

                # Genetate new tokens
                return TokenManager.generate_tokens(user)
        except TokenError as e:
            logger.warning(f"Token refresh error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during refresh: {str(e)}")
            raise TokenError(f"Token refresh failed: {str(e)}")
            
    @staticmethod
    def validate_token(token_string):
        """Validate token without using the database Returns tuple (is_valid, user_id, token_type)"""
        try:
            # first use PyJWT to decode without verification to get the algorithm
            unverified= jwt.decode(token_string, options={"verify_signature": False})
            alg = unverified.get('alg', settings.SIMPLE_JWT.get('ALGORITHM','HS256'))

            # Now properly decode and verify
            decoded = jwt.decode(token_string,
                                 settings.SIMPLE_JWT.get('SIGNING_KEY', settings.SECRET_KEY),
                                 algorithms=[alg],
                                 options={"verify_signature": True})
            # check token type
            token_type = decoded.get('token_type', decoded.get('type', 'access'))
            user_id = decoded.get('user_id')
            jti = decoded.get('jti')

            # check if token is blacklisted
            if jti and TokenManager.is_token_blacklisted(jti):
                logger.warning(f"Attempted to use balcklisted token with JTI: {jti}")
                return False, None, None
            
            # check expiration
            exp = decoded.get('exp', 0)
            if exp < time.time():
                logger.debug(f"Token expired at {datetime.fromtimestamp(exp).isoformat()}")
                return False,None,None
            return True, user_id, token_type
        except jwt.PyJWKError as e:
            logger.debug(f"Token validation error: {str(e)}")
            return False, None, None

    @staticmethod
    def _store_token_metadata(user_id, jti, expiry_seconds):
        """Store token metadata in cache for blacklisting"""
        try:
            # check if we're using Redis or standard cache
            redis_client = getattr(cache, 'client', None)
            if redis_client is not None:
                # Redis implementation
                user_tokens_key = f"user_tokens: {user_id}"
                pipe = redis_client.pipeline()
                pipe.sadd(user_tokens_key, jti)
                pipe.expire(user_tokens_key, int(expiry_seconds))
                pipe.execute()
            else:
                # Generate implementation fo LocMemCache
                user_tokens_key = f"user_tokens: {user_id}"
                token_set = cache.get(user_tokens_key, set())
                if not isinstance(token_set, set):
                    token_set = set()
                    cache.set(user_tokens_key, token_set, timeout=int(expiry_seconds))
        
        except Exception as e : 
            logger.error(f"Error storing token metadata: {str(e)}")

    @staticmethod
    def blacklist_token(jti):
        """Blacklist a token by JTI"""
        if not jti:
            return False
        
        # Add to blacklist with expiry
        blacklist_key = f"blacklisted_token:{jti}"
        cache.set(blacklist_key, True, timeout=settings. SIMPLE_JWT.get('BLACLISTED_TIMEOUT', 86400)) # default 1 day

    @staticmethod
    def is_token_blacklisted(jti):
        """check if a token is blacklited"""
        if not jti:
            return False
        blacklist_key = f"blacklisted_token: {jti}"
        return cache.get(blacklist_key)
    
    @staticmethod
    def blacklist_all_user_tokens(user_id):
        """Blacklist all tokens for a specific user"""
        try:
            user_tokens_key = f"user_tokens: {user_id}"
            redis_client = getattr(cache, 'client', None)
            if redis_client is not None:
                # redis implementation
                active_tokens = redis_client.smembers(user_tokens_key)
                if not active_tokens:
                    return 0
                # Add each token to blacklist
                for jti in active_tokens:
                    TokenManager.blacklist_token(jti.decode('utf-8') if isinstance(jti, bytes) else jti)

                # clear the set
                cache.delete(user_tokens_key)
                return len(active_tokens)
            else:
                # Generic implementation for LocMemCache
                token_set = cache.get(user_tokens_key, set())
                if not token_set:
                    return 0
                # Blacklist each token
                for jti in token_set:
                    TokenManager.blacklist_token(jti)

                # clear the set
                cache.delete(user_tokens_key)
                return len(token_set)
            
        except Exception as e:
            logger.error(f"Error balcklisting user tokens: {str(e)}")
            return 0