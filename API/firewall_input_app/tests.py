# Create your tests here.
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from config_app.models import Interface
from firewall_input_app.models import InputFirewall


class FirewallInputTest(APITestCase):
    fixtures = ['firewall_input_app/fixtures/test_data.json']

    def test_create_role1(self):
        url = reverse('input-policy-list')
        Interface.objects.create(
            name="eth2",
            description="",
            alias="eth0",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        data = {
            'source': {
                'src_network_list': [],
                'src_interface_list': ['eth2'],

            },

            'name': 'web',
            'is_log_enabled': False,
            'is_enabled': True,
            'permission': 'admin',
            'service_list': ['web'],

        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(InputFirewall.objects.all().count(), 1)

    def test_create_role2(self):
        url = reverse('input-policy-list')
        data = {
            'source': {
                'src_network_list': [],
                'src_interface_list': [],

            },

            'name': 'web',
            'is_log_enabled': False,
            'is_enabled': True,
            'permission': 'admin',
            'service_list': ['web'],

        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(InputFirewall.objects.all().count(), 1)

    def test_create_role3(self):
        url = reverse('input-policy-list')

        data = {
            'source': {
                'src_network_list': [1],
                'src_interface_list': [],

            },

            'name': 'web',
            'is_log_enabled': False,
            'is_enabled': True,
            'permission': 'admin',
            'service_list': ['ping'],

        }

        response = self.client.post(url, data, format='json')
        self.assertEquals(response.status_code, status.HTTP_201_CREATED)
        self.assertEquals(InputFirewall.objects.all().count(), 1)

    def test_create_role4(self):
        url = reverse('input-policy-list')
        data = {
            'source': {
                'src_network_list': [1, 2, 3],
                'src_interface_list': [],

            },

            'name': 'web',
            'is_log_enabled': False,
            'is_enabled': True,
            'permission': 'admin',
            'service_list': ['ping', 'cli', 'ipsec', 'web'],

        }

        response = self.client.post(url, data, format='json')
        self.assertEquals(response.status_code, status.HTTP_201_CREATED)
        self.assertEquals(InputFirewall.objects.all().count(), 1)

    def test_create_role5(self):
        url = reverse('input-policy-list')
        data = {
            'source': {
                'src_network_list': [1, 2, 3],
                'src_interface_list': [],

            },

            'name': 'web',
            'is_log_enabled': True,
            'is_enabled': True,
            'permission': 'admin',
            'service_list': ['https', 'web', 'ipsec', 'cli'],

        }

        response = self.client.post(url, data, format='json')
        self.assertEquals(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEquals(InputFirewall.objects.all().count(), 0)

    def test_create_role6(self):
        url = reverse('input-policy-list')

        Interface.objects.create(
            name="eth2",
            description="",
            alias="eth0",
            ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
            gateway="",
            is_default_gateway=True,
            is_dhcp_enabled=True,
            type="",
            is_enabled=True,
            link_type="Ethernet",
            pppoe_username="",
            pppoe_password="",
            mtu=1500
        )

        data = {
            'source': {
                'src_network_list': [1, 2, 3],
                'src_interface_list': ['eth2'],

            },

            'name': 'web',
            'is_log_enabled': False,
            'is_enabled': True,
            'permission': 'admin',
            'service_list': ['ping', 'cli', 'ipsec', 'web'],

        }

        response = self.client.post(url, data, format='json')
        self.assertEquals(response.status_code, status.HTTP_201_CREATED)
        self.assertEquals(InputFirewall.objects.all().count(), 1)

        data = {
            'source': {
                'src_network_list': [1, 2, 3],
                'src_interface_list': ['eth2'],

            },

            'name': 'web',
            'is_log_enabled': False,
            'is_enabled': True,
            'permission': 'admin',
            'service_list': ['ping', 'web'],

        }

        response = self.client.post(url, data, format='json')
        self.assertEquals(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEquals(InputFirewall.objects.all().count(), 1)

    # def test_put_role1(self):
    #     Interface.objects.create(
    #
    #         name="eth0",
    #         description="",
    #         alias="eth1",
    #         ip_list=[{"ip": "9.9.9.9", "mask": "255.255.255.255"}],
    #         gateway="",
    #         is_default_gateway=True,
    #         is_dhcp_enabled=True,
    #         type="",
    #         is_enabled=True,
    #         link_type="Ethernet",
    #         pppoe_username="",
    #         pppoe_password="",
    #         mtu=1500
    #
    #     )
    #
    #     Source.objects.create(
    #         pk=1,
    #         src_interface_list=[{1, 2}],
    #         src_network_list=[{'eth0'}]
    #     )
    #     InputFirewall.objects.create(
    #         pk=2,
    #         name='default cli',
    #         is_log_enabled='False',
    #         is_enabled='True',
    #         permission='admin',
    #         service_list='{ssh}',
    #         )
    #
    #     url = reverse('input-policy-detail', kwargs={'pk': 2})
    #     data = {
    #         'source': {
    #             'src_network_list': [1, 2, 3],
    #             'src_interface_list': ['eth0'],
    #
    #         },
    #
    #         'name': 'default cli',
    #         'is_log_enabled': False,
    #         'is_enabled': True,
    #         'permission': 'admin',
    #         'service_list': ['ssh'],
    #
    #     }
    #
    #     response = self.client.put(url, data, format='json')
    #     self.assertEquals(response.status_code, status.HTTP_200_OK)
    #     self.assertEquals(Interface.objects.all().count(), 1)
