from django.contrib import admin

# Register your models here.
from firewall_input_app.models import InputFirewall, Source, Apply

admin.site.register(InputFirewall)
admin.site.register(Source)
admin.site.register(Apply)
