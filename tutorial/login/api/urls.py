from django.urls import include, path

from . import views

urlpatterns = [
    path('', views.ListTodo.as_view()),
    path('<int:pk>/', views.DetailTodo.as_view()),
    path('rest-auth/', include('rest_auth.urls')),   
]

