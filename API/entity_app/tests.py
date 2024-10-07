from django.urls import reverse
from rest_framework import status

from api.settings import TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD
from entity_app.models import Address, Schedule, Service
from utils.test.helpers import CustomAPITestCase, add_test_vpn2

username = TEST_ADMIN_USERNAME
password = TEST_ADMIN_PASSWORD


class AddressTest(CustomAPITestCase):
    def test_create_ip_address(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'ip',
                                     'value_list': ['10.10.10.10']}
                                    , format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_required_field1(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'ip'}
                                    , format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_required_field2(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'ip',
                                     'value_list': []}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_required_field3(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'ip',
                                     'value_list': ["test"]}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_ip_address_invalid_format(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'ip', 'value_list': ['10']},
                                    format='json')
        # print("response:", response.content.decode('utf8'))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_ip_range(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'ip',
                                     'value_list': ['10.10.10.10-10.10.10.30']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_ip_range_invalid_format(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'ip',
                                     'value_list': ['10.10.10.10-30']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_subnet(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'ip',
                                     'value_list': ['10.10.10.0/24']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_subnet_invalid_mask(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'ip',
                                     'value_list': ['10.10.10.0/33']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_subnet_invalid_format(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'ip',
                                     'value_list': ['10.10.10.0/a']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_mac(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'mac',
                                     'value_list': ['11:22:33:44:aa:AA']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_mac_invalid_format1(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'mac',
                                     'value_list': ['11:22:33:44:55:rr']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_mac_invalid_format2(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'mac',
                                     'value_list': ['11:22:33:44:55:66:rr']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_mac_invalid_format3(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'mac',
                                     'value_list': ['11:22:33:44-55:66']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_mac_invalid_format4(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'mac',
                                     'value_list': ['11:2:33:44:55:66']},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_mac_invalid_format5(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'mac',
                                     'value_list': []}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_mac_invalid_format6(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'mac',
                                     'value_list': ["test"]}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_fqdn(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'fqdn',
                                     'value_list': ["test.test"]},
                                    format='json')
        # print("response:", response.content.decode('utf8'))
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_fqdn_invalid_format1(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'fqdn',
                                     'value_list': []},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_fqdn_invalid_format2(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'fqdn',
                                     'value_list': ["test"]},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_fqdn_invalid_format3(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'fqdn',
                                     'value_list': ["test-com"]},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_fqdn_invalid_format4(self):
        url = reverse('address-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc', 'type': 'fqdn',
                                     'value_list': ["10.1.1.10"]},
                                    format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_address(self):
        Address.objects.create(
            id=1,
            name='addr1',
            description='addr desc',
            type='ip',
            value_list=['20.20.20.20']
        )
        self.assertEqual(Address.objects.all().count(), 1)
        url = reverse('address-detail', kwargs={'pk': 1})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Address.objects.all().count(), 0)

    def test_delete_address_404(self):
        url = reverse('address-detail', kwargs={'pk': 1})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_put_address_name(self):
        Address.objects.create(
            id=1,
            name='addr1',
            description='addr desc',
            type='ip',
            value_list=['20.20.20.20']
        )
        url = reverse('address-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'new_address', 'description': 'addr desc', 'type': 'ip',
                                         'value_list': ['20.20.20.20']}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Address.objects.get(id=1).name, 'new_address')

    def test_put_address_type(self):
        Address.objects.create(
            id=1,
            name='addr1',
            description='addr desc',
            type='ip',
            value_list=['20.20.20.20']
        )
        url = reverse('address-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'new_address', 'description': 'addr desc', 'type': 'mac',
                                         'value_list': ['20.20.20.20']}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # print("response:", response.content.decode('utf8'))
        self.assertEqual(Address.objects.get(id=1).type, 'ip')

    def test_patch_address_type_value(self):
        Address.objects.create(
            id=1,
            name='addr1',
            description='addr desc',
            type='ip',
            value_list=['20.20.20.20']
        )
        url = reverse('address-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'type': 'mac', 'value_list': ['11:22:33:44:55:66'], 'name': 'addr1',
                                         'description': 'addr desc'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Address.objects.get(id=1).type, 'mac')
        self.assertEqual(Address.objects.get(id=1).value_list, ['11:22:33:44:55:66'])

    def test_patch_address_type_value_invalid_format(self):
        Address.objects.create(
            id=1,
            name='addr1',
            description='addr desc',
            type='ip',
            value_list=['20.20.20.20']
        )
        url = reverse('address-detail', kwargs={'pk': 1})
        response = self.client.patch(url, {'type': 'mac', 'value_list': ['11:22:33:44:55:66']}, format='json')
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_update_vpn_address(self):
        Address.objects.create(
            id=1,
            name='addr1',
            description='addr desc',
            type='ip',
            value_list=['111.12.1.11']
        )
        Address.objects.create(
            id=2,
            name='addr2',
            description='addr desc',
            type='ip',
            value_list=['121.12.1.11']
        )
        Address.objects.create(
            id=3,
            name='addr3',
            description='addr desc',
            type='ip',
            value_list=['121.12.13.33']
        )
        add_test_vpn2()
        url = reverse('address-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'new_address', 'description': 'addr desc', 'type': 'ip',
                                         'value_list': ['20.20.20.20/24']}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_vpn_address2(self):
        Address.objects.create(
            id=1,
            name='addr1',
            description='addr desc',
            type='ip',
            value_list=['111.12.1.11']
        )
        Address.objects.create(
            id=2,
            name='addr2',
            description='addr desc',
            type='ip',
            value_list=['121.12.1.11']
        )
        Address.objects.create(
            id=3,
            name='addr3',
            description='addr desc',
            type='ip',
            value_list=['121.12.13.33']
        )
        add_test_vpn2()
        url = reverse('address-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'new_address', 'description': 'addr desc', 'type': 'ip',
                                         'value_list': ['20.20.20.20', '3.3.3.3']}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_vpn_address3(self):
        Address.objects.create(
            id=1,
            name='addr1',
            description='addr desc',
            type='ip',
            value_list=['111.12.1.11']
        )
        Address.objects.create(
            id=2,
            name='addr2',
            description='addr desc',
            type='ip',
            value_list=['121.12.1.11']
        )
        Address.objects.create(
            id=3,
            name='addr3',
            description='addr desc',
            type='ip',
            value_list=['121.12.13.33']
        )
        add_test_vpn2()
        url = reverse('address-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'new_address', 'description': 'addr desc', 'type': 'mac',
                                         'value_list': ['11:22:33:44:55:66']}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ScheduleTest(CustomAPITestCase):
    def test_create_schedule1(self):
        url = reverse('schedule-list')
        response = self.client.post(url, {'name': 'sch1',
                                          'description': 'new schedule',
                                          'start_time': '02:03:04',
                                          'end_time': '10:03:04',
                                          'start_date': '2017-05-05',
                                          'end_date': '2017-07-05',
                                          'days_of_week': {"sunday": True,
                                                           "monday": True,
                                                           "tuesday": False,
                                                           "wednesday": False,
                                                           "thursday": True,
                                                           "friday": False,
                                                           "saturday": True}
                                          }, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_schedule2(self):
        url = reverse('schedule-list')
        response = self.client.post(url, {'name': 'sch1',
                                          'description': 'new schedule',
                                          'start_time': '02:03:04',
                                          'end_time': '10:03:04',
                                          'start_date': '2017-05-05',
                                          'end_date': '2017-07-05',
                                          'days_of_week': {"sunday": "1",
                                                           "monday": True,
                                                           "tuesday": False,
                                                           "wednesday": False,
                                                           "thursday": True,
                                                           "friday": False,
                                                           "saturday": True}
                                          }, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_schedule3(self):
        url = reverse('schedule-list')
        response = self.client.post(url, {'name': 'sch1',
                                          'description': 'new schedule',
                                          'days_of_week': {"sunday": True,
                                                           "monday": True,
                                                           "tuesday": False,
                                                           "wednesday": False,
                                                           "thursday": True,
                                                           "friday": False,
                                                           "saturday": True}
                                          }, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_schedule4(self):
        url = reverse('schedule-list')
        response = self.client.post(url, {'name': 'sch1',
                                          'description': 'new schedule',
                                          'start_time': '01:03:04',
                                          'end_time': '10:03:02',
                                          'start_date': '2017-05-05',
                                          'end_date': '2017-06-05',
                                          'days_of_week': {"sunday": False,
                                                           "monday": True,
                                                           "tuesday": False, }
                                          }, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_schedule5(self):
        url = reverse('schedule-list')
        response = self.client.post(url, {'name': 'sch1',
                                          'description': 'new schedule',
                                          'start_time': '06:03:04',
                                          'end_time': '10:03:61',
                                          'start_date': '2017-05-05',
                                          'end_date': '2017-06-05',
                                          'days_of_week': {}
                                          }, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_schedule6(self):
        url = reverse('schedule-list')
        response = self.client.post(url, {'name': 'sch1',
                                          'description': 'new schedule',
                                          'start_time': '02:03:04',
                                          'end_time': '10:03:04',
                                          'start_date': '2017-08-05',
                                          'end_date': '2010-07-05',
                                          'days_of_week': {"sunday": True,
                                                           "monday": True,
                                                           "tuesday": False,
                                                           "wednesday": False,
                                                           "thursday": True,
                                                           "friday": False,
                                                           "saturday": True}
                                          }, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_schedule7(self):
        url = reverse('schedule-list')
        response = self.client.post(url, {'name': 'sch1',
                                          'description': 'new schedule',
                                          'start_time': '02:03:04',
                                          'end_time': '10:03:04',
                                          'start_date': '2017-05-05',
                                          'end_date': '2017-07-05',
                                          'days_of_week': {"sunday": "1",
                                                           "monday": True,
                                                           "tuesday": False,
                                                           "wednesday": False,
                                                           "thursday": 23,
                                                           "friday": False,
                                                           "saturday": True}
                                          }, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_schedule(self):
        Schedule.objects.create(
            id=1,
            name='sch1',
            description='new schedule',
            start_time='02:03:04',
            end_time='10:03:04',
            start_date='2017-05-05',
            end_date='2017-07-05',
            days_of_week={"sunday": True,
                          "monday": True,
                          "tuesday": False,
                          "wednesday": False,
                          "thursday": True,
                          "friday": False,
                          "saturday": True}
        )
        url = reverse('schedule-detail', kwargs={'pk': 1})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_put_schedule(self):
        Schedule.objects.create(
            id=1,
            name='sch1',
            description='new schedule',
            start_time='02:03:04',
            end_time='10:03:04',
            start_date='2017-05-05',
            end_date='2017-07-05',
            days_of_week={"sunday": True,
                          "monday": True,
                          "tuesday": False,
                          "wednesday": False,
                          "thursday": True,
                          "friday": False,
                          "saturday": True}
        )
        url = reverse('schedule-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'sch1', 'description': 'new schedule test', 'start_time': '02:03:04',
                                         'end_time': '10:03:04', 'start_date': '2017-05-05', 'end_date': '2017-07-05',
                                         'days_of_week': {"sunday": True,
                                                          "monday": True,
                                                          "tuesday": False,
                                                          "wednesday": False,
                                                          "thursday": True,
                                                          "friday": False,
                                                          "saturday": True}}, format='json')
        # print("response:", response.content.decode('utf8'))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Schedule.objects.get(id=1).description, 'new schedule test')

    def test_patch_schedule_405(self):
        Schedule.objects.create(
            id=1,
            name='sch1',
            description='new schedule',
            start_time='02:03:04',
            end_time='10:03:04',
            start_date='2017-05-05',
            end_date='2017-07-05',
            days_of_week={"sunday": True,
                          "monday": True,
                          "tuesday": False,
                          "wednesday": False,
                          "thursday": True,
                          "friday": False,
                          "saturday": True}
        )
        url = reverse('schedule-detail', kwargs={'pk': 1})
        response = self.client.patch(url, {'start_time': '2017-05-05'})
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_patch_schedule_not_unique_name(self):
        Schedule.objects.create(
            id=1,
            name='sch1',
            description='new schedule',
            start_time='6:03:04',
            end_time='10:23:04',
            start_date='2017-05-25',
            end_date='2017-07-25',
            days_of_week={"sunday": True,
                          "monday": True,
                          "tuesday": False,
                          "wednesday": True,
                          "thursday": True,
                          "friday": False,
                          "saturday": True}
        )
        Schedule.objects.create(
            id=2,
            name='sch2',
            description='new schedule',
            start_time='11:03:04',
            end_time='10:23:04',
            start_date='2017-08-05',
            end_date='2017-09-05',
            days_of_week={"sunday": False,
                          "monday": True,
                          "tuesday": False,
                          "wednesday": False,
                          "thursday": True,
                          "friday": False,
                          "saturday": True}
        )
        url = reverse('schedule-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'sch2',
                                         'description': 'new schedule',
                                         'start_time': '02:03:04',
                                         'end_time': '10:03:04',
                                         'start_date': '2017-05-05',
                                         'end_date': '2017-07-05',
                                         'days_of_week': {"sunday": True,
                                                          "monday": True,
                                                          "tuesday": True,
                                                          "wednesday": False,
                                                          "thursday": True,
                                                          "friday": False,
                                                          "saturday": True}
                                         }, format='json')
        # print("response:", response.content.decode('utf8'))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ServiceTest(CustomAPITestCase):
    def test_create_service2(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr1', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["8432"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service3(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr2', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["84-96"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service4(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr3', 'description': 'addr desc',
                                     'protocol': {"udp": {"src": ["8432"], "dst": ["45-98"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service5(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr4', 'description': 'addr desc',
                                     'protocol': {"udp": {"dst": ["5-88"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service6(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'ip1', 'description': 'addr desc',
                                     'protocol': {"ip": {"protocol_number": "84"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service7(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'icmp1', 'description': 'addr desc',
                                     'protocol': {"icmp": {"code": "2", "type": "8"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service8(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'icmp2', 'description': 'addr desc',
                                     'protocol': {"icmp": {"type": "25"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service9(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr5', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["16"]}, "udp": {"src": ["2"], "dst": ["444"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service10(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr5', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["156"]}, "udp": {"src": ["29"], "dst": ["644"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service11(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr5', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["15"], "dst": ["4"]},
                                                  "udp": {"src": ["9"], "dst": ["68"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service12(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr6', 'description': 'addr desc',
                                     'protocol': {"tcp": {"dst": ["46"]}, "udp": {"src": ["999"], "dst": ["680"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service13(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr7', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["105"], "dst": ["47"]}, "udp": {"dst": ["8"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service14(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr8', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["175"], "dst": ["47"]}, "udp": {"src": ["779"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service15(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr9', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["1577"]}, "udp": {"dst": ["6778"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service16(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr10', 'description': 'addr desc',
                                     'protocol': {"tcp": {"dst": ["4899"]}, "udp": {"dst": ["6258"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service17(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr11', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["7015"], "dst": ["9654"]}, "udp": {"src": ["9014"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_service18(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr12', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["1985"], "dst": ["4test"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service19(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr13', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["65536"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service20(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr14', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["15v"], "dst": ["4a"]}, "udp": {"src": ["90"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service21(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr15', 'description': 'addr desc',
                                     'protocol': {"ip": {"protocol_number": "255"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service22(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr16', 'description': 'addr desc',
                                     'protocol': {"ip": {"protocol_number": "test"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service23(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr17', 'description': 'addr desc',
                                     'protocol': {"icmp": {"code": "test", "type": "84"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service24(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr18', 'description': 'addr desc',
                                     'protocol': {"icmp": {"code": "256", "type": "84"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service25(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr19', 'description': 'addr desc',
                                     'protocol': {"icmp": {"code": "6", "type": "test"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service26(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr20', 'description': 'addr desc',
                                     'protocol': {"icmp": {"code": "9", "type": "256"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service27(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr21', 'description': 'addr desc',
                                     'protocol': {"icmp": {"type": "test"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service28(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr22', 'description': 'addr desc',
                                     'protocol': {"icmp": {"type": "256"}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service29(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr5', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["15-9"], "dst": ["4"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service30(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr5', 'description': 'addr desc',
                                     'protocol': {"tcp": {"src": ["1"], "dst": ["99-2"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service31(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr5', 'description': 'addr desc',
                                     'protocol': {"udp": {"src": ["15-9"], "dst": ["84"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_service32(self):
        url = reverse('service-list')
        response = self.client.post(url,
                                    {'name': 'addr5', 'description': 'addr desc',
                                     'protocol': {"udp": {"src": ["1003"], "dst": ["99-2"]}}}
                                    , format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_service1(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"tcp": {"src": ["8432"], "dst": ["8432", "45-98"]}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_service2(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"tcp": {"src": ["16"]}, "udp": {"src": ["2"], "dst": ["444"]}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_service3(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"ip": {"protocol_number": "84"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_service4(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"icmp": {"code": "92", "type": "84"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_service5(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"icmp": {"type": "56"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_service_404(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"icmp": {"type": "56"}}
        )
        url = reverse('service-detail', kwargs={'pk': 2})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_put_service1(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"tcp": {"src": ["8432"], "dst": ["8432", "45-98"]}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"tcp": {"src": ["8432"], "dst": ["8432", "45-98"]}}},
                                   format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_service2(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"udp": {"src": ["843-999"], "dst": ["45-98"]}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"udp": {"src": ["84"]}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_service3(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"tcp": {"src": ["16"]}, "udp": {"src": ["2"], "dst": ["444"]}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'test', 'description': 'desc',
                                         'protocol': {"tcp": {"src": ["36-54"]}, "udp": {"src": ["22"], "dst": ["4"]}}},
                                   format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_service4(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"ip": {"protocol_number": "25"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"ip": {"protocol_number": "25"}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_service5(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"icmp": {"code": "2", "type": "84"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"icmp": {"code": "13", "type": "82"}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_service6(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"icmp": {"code": "2", "type": "84"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"icmp": {"type": "24"}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_service7(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"icmp": {"type": "56"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"icmp": {"type": "56"}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_put_service8(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"tcp": {"src": ["8432"], "dst": ["8432", "45-98"]}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"tcp": {"src": ["test"], "dst": ["8432", "45-98"]}}},
                                   format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_service9(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"udp": {"src": ["843-999"], "dst": ["45-98"]}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"udp": {"src": ["84-9"]}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_service10(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"tcp": {"src": ["16"]}, "udp": {"src": ["2"], "dst": ["444"]}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'test', 'description': 'desc',
                                         'protocol': {"tcp": {"src": ["36-54"]},
                                                      "udp": {"src": ["22"], "dst": ["test"]}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_service11(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"ip": {"protocol_number": "25"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"ip": {"protocol_number": "255"}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_service12(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"ip": {"protocol_number": "25"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"ip": {"protocol_number": "HAHAHA"}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_service13(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"icmp": {"code": "2", "type": "84"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"icmp": {"code": "256", "type": "82"}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_service14(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"icmp": {"code": "2", "type": "84"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"icmp": {"type": "256"}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_put_service15(self):
        Service.objects.create(
            id=1,
            name='service1',
            description='desc',
            is_user_defined='True',
            protocol={"icmp": {"type": "56"}}
        )
        url = reverse('service-detail', kwargs={'pk': 1})
        response = self.client.put(url, {'name': 'service1', 'description': 'desc',
                                         'protocol': {"icmp": {"type": "test"}}}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
