import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "root_runner.wsgi")

SECRET_KEY = ')qp3rcpo)_9rszk=rb9i&1cf@akha65rgnl=^z1@_y#!(bra+h'

DEBUG = True

ALLOWED_HOSTS = ['*']

ROOT_URLCONF = 'root_runner.urls'

WSGI_APPLICATION = 'root_runner.wsgi.application'


application = get_wsgi_application()
