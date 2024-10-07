from django.apps import AppConfig


class ConfigurationAppConfig(AppConfig):
    name = 'config_app'

    def ready(self):
        from config_app import signals
        signals.dummy_function()
