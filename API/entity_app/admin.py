from django.contrib import admin

from .models import Address, Schedule, Service


class AddressAdmin(admin.ModelAdmin):
    list_display = ['id', 'name']
    search_fields = ['name', 'type']
    list_filter = ['type']


class ServiceAdmin(admin.ModelAdmin):
    list_display = ['id', 'name']


class ScheduleAdmin(admin.ModelAdmin):
    list_display = ['id', 'name']


admin.site.register(Address, AddressAdmin)
admin.site.register(Service, ServiceAdmin)
admin.site.register(Schedule, ScheduleAdmin)
