from django.contrib import admin

from firewall_app.models import Policy, SourceDestination


class PolicyAdmin(admin.ModelAdmin):
    list_display = ('name', 'id', 'nat', 'is_enabled', 'status', 'next_policy')
    search_fields = ('name', 'id', 'nat', 'is_enabled')
    ordering = ('id',)


admin.site.register(Policy, PolicyAdmin)
admin.site.register(SourceDestination)
