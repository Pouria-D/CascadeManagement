from rest_framework import routers

from user_app.views import UserViewSet, GroupViewSet, MembershipViewSet, AccessTimeViewSet, AccountingViewSet

router = routers.DefaultRouter()
router.register(r'clients', UserViewSet, base_name='client')
router.register(r'groups', GroupViewSet, base_name='group')
router.register(r'memberships', MembershipViewSet, base_name='membership')
router.register(r'access-times', AccessTimeViewSet, base_name='access-time')
router.register(r'quotas', AccountingViewSet, base_name='accounting')
