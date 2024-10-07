from django.contrib import admin

from user_app.models import User, Group, AccessTime, Accounting


class UserAdmin(admin.ModelAdmin):
    list_display = ['username']


class GroupAdmin(admin.ModelAdmin):
    list_display = ['name']


class AccessTimeAdmin(admin.ModelAdmin):
    list_display = ['name']


class AccountingAdmin(admin.ModelAdmin):
    list_display = ['name']


admin.site.register(User, UserAdmin)
admin.site.register(Group, GroupAdmin)
admin.site.register(AccessTime, AccessTimeAdmin)
admin.site.register(Accounting, AccountingAdmin)
