"""
Django settings for consumer project.

Generated by 'django-admin startproject' using Django 3.2.12.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""
import environ
import os

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env()
environ.Env.read_env()

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-i6cz3cg($+21yt=8&!_f65(5ubxo*3i5ur^8^jzfw(cd=4hg5%'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

INTERNAL_APPS = [
    'home',
    'newauth'
]

EXTERNAL_APPS = [
    'mozilla_django_oidc'
]

INSTALLED_APPS = DJANGO_APPS + INTERNAL_APPS + EXTERNAL_APPS

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'consumer.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'consumer.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': env('POSTGRES_DATABASE_NAME'),
        'USER': env('POSTGRES_DATABASE_USER'),
        'PASSWORD': env('POSTGRES_DATABASE_PASSWORD'),
        'HOST': 'localhost',
        'PORT': env('POSTGRES_DATABASE_PORT'),                      # Set to empty string for default.
    }
}



# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# OIDC Settings
AUTHENTICATION_BACKENDS = (
    #"django.contrib.auth.backends.ModelBackend",
    # OIDC authentication backend -> You can use the default (from mozilla's docs)
    # or create a custom Backend, as I have done
    'consumer.utils.AuthManager',

    # `allauth` specific authentication methods, such as login by e-mail
    #'allauth.account.auth_backends.AuthenticationBackend',
)

OIDC_RP_CLIENT_ID = env('OIDC_RP_CLIENT_ID') #                           -
OIDC_RP_CLIENT_SECRET = env('OIDC_RP_CLIENT_SECRET') #                   |
OIDC_OP_AUTHORIZATION_ENDPOINT = env('OIDC_OP_AUTHORIZATION_ENDPOINT') #| -> Acquired
OIDC_OP_TOKEN_ENDPOINT = env('OIDC_OP_TOKEN_ENDPOINT') #                 |    from
OIDC_OP_USER_ENDPOINT = env('OIDC_OP_USER_ENDPOINT') #                   |    provider
#OIDC_RP_SCOPES = env('OIDC_RP_SCOPES') #                                 -
OIDC_OP_LOGOUT_URL_METHOD = 'consumer.utils.logout_redirect_uri'
OIDC_STORE_ID_TOKEN = True
OIDC_USE_NONCE = False
OIDC_CALLBACK_CLASS = 'newauth.views.CallbackView'
OIDC_AUTHENTICATE_CLASS = 'newauth.views.AuthView'

#SESSION_ENGINE = "django.contrib.sessions.backends.cache"

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient"
        }
    }
}

SESSION_COOKIE_SECURE =  not DEBUG[]