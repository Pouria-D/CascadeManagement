from django.contrib import admin

from update_app.models import Update


class UpdateAdmin(admin.ModelAdmin):
    list_display = ('id', 'new_version', 'description', 'status')


admin.site.register(Update, UpdateAdmin)
