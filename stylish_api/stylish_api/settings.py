import os
from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent
from decouple import config
# SECRET_KEY = 'django-insecure-e!6dbs%=69(s*oulsa*5wt!pwk@o*ulp^$xj^%=pg)^m+2dw!d'
SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default = '*', cast=lambda v:[s.strip() for s in v.split(',')])


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # third party apps
    'rest_framework',
    'corsheaders',
    'drf_yasg',

    # local apps
    'authentication',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'stylish_api.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'stylish_api.wsgi.application'

AUTH_USER_MODEL = 'authentication.User'
# Database
# https://docs.djangoproject.com/en/6.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME':config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD':config('DB_PASSWORD'),
        'HOST': config('DB_HOST'),
        'PORT': config('DB_PORT', cast=int)
    }
}


# Password validation
# https://docs.djangoproject.com/en/6.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.0/howto/static-files/

STATIC_URL = 'static/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Rest framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}


SIMPLE_JWT={
    'ACCESS_TOKEN_LIFETIME' : timedelta(minutes = 15),
    'REFRESH_TOKEN_LIFETIME' : timedelta(days = 14),
    'ROTATE_REFRESH_TOKENS' : True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM' : 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD' : 'id',
    'USER_ID_CLAIM' : 'user_id',
    'AUTH_TOKEN_CLASSES' : ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM' : 'token_type',
}

# JWT cookies settings
JWT_COOKIE_SECURE = False #Set to True in the production when using HTTPS
JWT_COOKIE_NAME = 'refresh_token'

SESSION_COOKIE_DOMAIN = '.yourdomain.com'#Note the leading dot for subdomain support
# For development
if DEBUG:
    SESSION_COOKIE_DOMAIN = None # or '127.0.0.1 for local devlopement
# cache settings
CACHES = {
    'default':{
        'BACKEND':'django.core.cache.backends.redis.RedisCache',
        'LOCATION':'redis://localhost:6376/0',
        'TIMEOUT': 3600, # Default cache timeout(1 hour)
        'OPTIONS':{
            'CLIENT_CLASS':'django_redis.client.DefaultClient',
            'SOCKET_CONNECT_TIMEOUT':5,#seconds
            'SOCKET_TIMEOUT': 5, #seconds
            'IGNORE_EXCEPTIONS': True,
        }
    }
}

# Fallback to in-memory cache if redis is unavailable
CACHES = {
    'default':{
        'BACKEND' : 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION':'unique-snowflake',
    }
}

EMAIL_VERIFICATION_TIMEOUT = 3600*24*3 #days verification link
MOBILE_VERIFICATION_REDIRECT = True #Emable mobile app redirection for verification

REQUIRE_EMAIL_VERIFICATION = True # weather to require email verification to use the app

APP_NAME = 'Stylish'

# Email settings
# Gmail SMTP

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = 'stylish <noreply@yourapp.com>'
CONTACT_EMAIL = 'support@stylish.com'

