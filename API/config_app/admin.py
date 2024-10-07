from django.contrib import admin

from config_app.models import Interface, Backup, DNSRecord, DNSConfig, Setting, Update, HighAvailability


class SettingAdmin(admin.ModelAdmin):
    list_display = ('key', 'data')


class BackupAdmin(admin.ModelAdmin):
    list_display = ('version', 'datetime', 'status')


admin.site.register(Interface)
admin.site.register(Backup, BackupAdmin)
admin.site.register(DNSConfig)
admin.site.register(DNSRecord)
admin.site.register(Setting, SettingAdmin)
admin.site.register(Update)
admin.site.register(HighAvailability)
