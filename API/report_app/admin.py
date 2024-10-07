from django.contrib import admin

from report_app.models import Notification


class NotificationAdmin(admin.ModelAdmin):
    list_display = ['source', 'message', 'details']
    search_fields = []


admin.site.register(Notification, NotificationAdmin)
