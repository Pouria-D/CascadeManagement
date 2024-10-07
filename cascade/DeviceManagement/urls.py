from django.urls import path
from DeviceManagement import views
from rest_framework.urlpatterns import format_suffix_patterns
from django.conf.urls import include, url
from django.contrib import admin
from DeviceManagement.views import DeviceViewSet, UserViewSet, ChangePasswordView
from rest_framework import renderers
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework import routers, viewsets
from django.contrib.auth import views as auth_views
from django.views.decorators.csrf import csrf_exempt

Device_list = DeviceViewSet.as_view({
    'get': 'list',
    'post': 'create'
})
Device_detail = DeviceViewSet.as_view({
    'get': 'retrieve',
    'put': 'update',
    'patch': 'partial_update',
    'delete': 'destroy'
})

user_list = UserViewSet.as_view({
    'get': 'list'
})
user_detail = UserViewSet.as_view({
    'get': 'retrieve'
})

urlpatterns = format_suffix_patterns([
    path('api/devices/', Device_list, name='Device-list'),
    #path('snippet/<int:pk>/', Device_detail, name='snippet-detail'),
    path('api/users/', user_list, name='user-list'),
])


class DefaultRouterWithSimpleViews(routers.DefaultRouter):
    """
    Extends functionality of DefaultRouter adding possibility
    to register simple API views, not just Viewsets.
    """

    def get_routes(self, viewset):
        """
        Checks if the viewset is an instance of ViewSet,
        otherwise assumes it's a simple view and does not run
        original `get_routes` code.
        """
        if issubclass(viewset, viewsets.ViewSetMixin):
            return super(DefaultRouterWithSimpleViews, self).get_routes(viewset)

        return []

    def get_urls(self):
        """
        Append non-viewset views to the urls
        generated by the original `get_urls` method.
        """
        # URLs for simple views
        ret = []
        for prefix, viewset, basename in self.registry:

            # Skip viewsets
            if issubclass(viewset, viewsets.ViewSetMixin):
                continue

            # URL regex
            regex = '{prefix}{trailing_slash}$'.format(
                prefix=prefix,
                trailing_slash=self.trailing_slash
            )

            # The view name has to have suffix "-list" due to specifics
            # of the DefaultRouter implementation.
            ret.append(url(
                regex, viewset.as_view(),
                name='{0}-list'.format(basename)
            ))

        # Format suffixes
        ret = format_suffix_patterns(ret, allowed=['json', 'html'])

        # Prepend URLs for viewsets and return
        return super(DefaultRouterWithSimpleViews, self).get_urls() + ret


# Create a router and register our viewsets with it.

router = DefaultRouter()
router = DefaultRouterWithSimpleViews()

router.register(r'api/devices', views.DeviceViewSet)
router.register(r'api/users', views.UserViewSet)
router.register(r'api/change-password', views.ChangePasswordView, 'change password')

# The API URLs are now determined automatically by the router.
urlpatterns = [
    #path('about/', AboutView.as_view()),
    #path('ws/Devices/', Device_list, name='Device-list'),
    path('api/remote/devices/', Device_list, name='Remote_device-list'), 
    path('api/change-password/', ChangePasswordView.as_view(), name='change-password'),
   
    #path('accounts/', include('rest_framework.urls')),
    #path('api-auth/', include('rest_framework.urls')),
    #path('accounts/logout', include(router.urls) ),
    path('', include(router.urls)),
]

"""

    path('^login/$', auth_views.LoginView, name='login'),
    path('^logout/$', auth_views.LogoutView, name='logout'),
    path('admin/', admin.site.urls),
######### using view not view sets ...
urlpatterns = [
    path('snippet/', views.SnippetList.as_view(), name='snippet-list'),
    path('snippet/<int:pk>/', views.SnippetDetail.as_view(), name='snippet-detail'),
    path('users/', views.UserList.as_view(), name='user-list'),
    path('users/<int:pk>/', views.UserDetail.as_view(), name='user-detail'),
    path('api-auth/', include('rest_framework.urls')),
    path('', views.api_root),
    path('snippet/<int:pk>/highlight/', views.SnippetHighlight.as_view(), name='snippet-highlight'),
]

urlpatterns = format_suffix_patterns(urlpatterns)

########## Functionally_based view !
urlpatterns = [
    path('snippet/', views.snippet_list),
    path('snippet/<int:pk>/', views.snippet_detail),
]

urlpatterns = format_suffix_patterns(urlpatterns)
"""