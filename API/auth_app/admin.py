from django.contrib import admin

from auth_app.models import Token, AdminLoginLock

admin.site.register(Token),
admin.site.register(AdminLoginLock)
