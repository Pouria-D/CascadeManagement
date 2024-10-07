from django.urls import reverse
from rest_framework import status

from api.settings import TEST_ADMIN_USERNAME, TEST_ADMIN_PASSWORD
from diagnosis_app.models import Diagnosis
from root_runner.sudo_utils import sudo_file_reader
from utils.config_files import TEST_PATH
from utils.test.helpers import CustomAPITestCase

username = TEST_ADMIN_USERNAME
password = TEST_ADMIN_PASSWORD


def check_file_content(file, content):
    status, file_content = sudo_file_reader(file)
    if status:
        if content not in file_content:
            return False
        return True


class DiagnosisTest(CustomAPITestCase):
    fixtures = ['config_app/fixtures/test_config.json']

    def tearDown(self):
        import os
        Diagnosis.objects.all().delete()
        cmd = 'rm -rf {}'.format(TEST_PATH)
        os.system(cmd)

    def test_ping_remote_endpoint_report(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'Ping',
                'type': ['ping'],
                'duration': 1,
                'local_host_report': None,
                'remote_host_report': None,
                'remote_endpoint_report': '192.168.15.82'
                }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # cmd = 'ping {} -w 5'.format(data['remote_endpoint_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))

    def test_ping_link_between_local_remote(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'Pinglink',
                'type': ['ping'],
                'duration': 1,
                'local_host_report': '192.168.15.72',
                'remote_host_report': '192.168.15.144',
                'remote_endpoint_report': None
                }
        response = self.client.post(url, data, format='json')
        # self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # cmd = 'ping {} -w 5'.format(data['local_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'ping {} -w 5'.format(data['remote_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'ping -I {} {} -w 5'.format(data['local_host_report'], data['remote_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))

    def test_ping_not_input_ip(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'Ping',
                'type': ['ping'],
                'duration': 1,
                'local_host_report': None,
                'remote_host_report': None,
                'remote_endpoint_report': None
                }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_ping_not_input_type(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'Test_ping',
                'type': None,
                'duration': 1,
                'local_host_report': '192.168.15.70',
                'remote_host_report': '192.168.15.144',
                'remote_endpoint_report': None
                }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_ping_not_input_local_or_remote_(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'Ping',
                'type': ['ping'],
                'duration': 1,
                'local_host_report': '192.168.15.70',
                'remote_host_report': None,
                'remote_endpoint_report': None
                }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_ping(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'Ping',
                'type': ['ping'],
                'duration': 1,
                'local_host_report': '192.168.15.70',
                'remote_host_report': '192.168.15.70',
                'remote_endpoint_report': '192.168.15.70'
                }
        response = self.client.post(url, data, format='json')

        # self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # cmd = 'ping {} -w 5'.format(data['local_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'ping {} -w 5'.format(data['remote_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'ping {} -w 5'.format(data['remote_endpoint_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'ping -I {} {} -w 5'.format(data['local_host_report'], data['remote_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))

    def test_mtr(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'Testping',
                'type': ['mtr'],
                'duration': 1,
                'local_host_report': None,
                'remote_host_report': '192.168.15.70',
                'remote_endpoint_report': '192.168.15.114'
                }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # cmd = 'mtr -r {}  -o LSDR NBAW VG JMXI'.format(data['remote_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'mtr -r {}  -o LSDR NBAW VG JMXI'.format(data['remote_endpoint_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))

    def test_mtr_ping(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'Testping',
                'type': ['mtr', 'ping'],
                'duration': 1,
                'local_host_report': '192.168.15.70',
                'remote_host_report': '192.168.15.70',
                'remote_endpoint_report': '192.168.15.114'
                }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # cmd = 'ping {} -w 5'.format(data['local_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'ping {} -w 5'.format(data['remote_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'ping {} -w 5'.format(data['remote_endpoint_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'ping -I {} {} -w 5'.format(data['local_host_report'], data['remote_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'mtr -r {}  -o "LSDR NBAW VG JMXI"'.format(data['remote_host_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'mtr -r {}  -o "LSDR NBAW VG JMXI"'.format(data['remote_endpoint_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))

    def test_mtr_ping(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'testpingmtr',
                'type': ['mtr', 'ping'],
                'duration': 1,
                'local_host_report': None,
                'remote_host_report': None,
                'remote_endpoint_report': '192.168.15.70'
                }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # cmd = 'ping {} -w 5'.format(data['remote_endpoint_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
        #
        # cmd = 'mtr -r {}  -o "LSDR NBAW VG JMXI"'.format(data['remote_endpoint_report'])
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))

    def test_conntrack(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'conntrack',
                'type': ['conntrack'],
                'duration': 1,
                'local_host_report': None,
                'remote_host_report': None,
                'remote_endpoint_report': None
                }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # cmd = "conntrack -L | grep 'ASSURED' | wc -l"
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))

    def test_ram_cpu(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'Testping',
                'type': ['ram_cpu'],
                'duration': 1,
                'local_host_report': None,
                'remote_host_report': None,
                'remote_endpoint_report': None
                }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_ram_cpu_conntrack(self):
        url = reverse('diagnosis-report-list')
        data = {'name': 'ramcpuconntrack',
                'type': ['ram_cpu'],
                'duration': 1,
                'local_host_report': None,
                'remote_host_report': None,
                'remote_endpoint_report': None
                }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # cmd = "conntrack -L | grep 'ASSURED' | wc -l"
        # self.assertTrue(check_file_content(COMMANDS_PATH, cmd))
