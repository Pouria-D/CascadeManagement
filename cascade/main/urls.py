"""main URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))

from django.contrib import admin
from django.urls import path , include

urlpatterns = [
    path('', include('DeviceManagement.urls')),
    path('admin/', admin.site.urls),
]
main URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path , include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token  # <-- Here
router = DefaultRouter(trailing_slash=False)

urlpatterns = [
    path('accounts/profile/', include('DeviceManagement.urls')),
    path('', include('DeviceManagement.urls')),
    # Redirect for login page ( when user directly go to login page by url << ..../api/accounts/login/ >> it will got address << .../accounts/profile >>)
    path('api/accounts/', include('rest_framework.urls')),
    path('api/admin/', admin.site.urls),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),  # <-- And here
    ]

