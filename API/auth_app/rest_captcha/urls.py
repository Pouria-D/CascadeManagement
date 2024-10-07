from django.conf.urls import url

from auth_app.rest_captcha import views

urlpatterns = [
    url(r'^$', views.RestCaptchaView.as_view(), name='rest_captcha'),
]
