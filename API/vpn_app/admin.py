from django.contrib import admin

from vpn_app.models import VPN


class VPNStatus(admin.ModelAdmin):
    list_display = ['name', 'tunnel', 'status']


admin.site.register(VPN, VPNStatus)
