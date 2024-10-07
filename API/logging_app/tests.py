from django.urls import reverse
from rest_framework import status

from utils.test.helpers import CustomAPITestCase


class GeneralLogTests(CustomAPITestCase):
    def test_get_general_log(self):
        url = reverse('general-log')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class AdminLogTests(CustomAPITestCase):
    def test_get_admin_log(self):
        url = reverse('admin-log')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class FirewallLogTests(CustomAPITestCase):
    def test_get_general_log(self):
        url = reverse('firewall-log')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class VPNLogTests(CustomAPITestCase):
    def test_get_general_log(self):
        url = reverse('vpn-log')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
