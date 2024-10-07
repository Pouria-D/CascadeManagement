from django.apps import AppConfig


class ReportAppConfig(AppConfig):
    name = 'report_app'

    def ready(self):
        from report_app import signals
