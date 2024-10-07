from report_app.models import Notification


def create_notification(source, item, message, severity, request_username=None, details=None, is_deletable=True):
    if request_username:
        user = request_username
    else:
        user = 'system'
    # try:
    #     notification = Notification.objects.get(source=source, item=item)
    #     notification.message = message
    #     notification.severity = severity
    #     notification.details = details
    #     notification.user = user
    #     notification.save()
    # except Notification.DoesNotExist:
    #     Notification.objects.create(
    #         source=source,
    #         item=item,
    #         message=message,
    #         severity=severity,
    #         details=details,
    #         user=user
    #     )

    # NOTE: with below code I found lines with same source and item!!!
    Notification.objects.update_or_create(
        source=source,
        item=item,
        message=message,
        severity=severity,
        details=details,
        user=user,
        is_deletable=is_deletable
    )
