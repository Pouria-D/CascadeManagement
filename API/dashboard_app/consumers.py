import json
from threading import Thread
from time import sleep

import requests
from channels.generic.websocket import JsonWebsocketConsumer

from config_app.utils import this_system_is_master, ha_read_status
from utils.system_info import SystemInfo


class HAMasterConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            result = dict()
            pcs_status = ha_read_status()

            try:
                result['is-master'] = this_system_is_master(pcs_status)
                self.send_json(result)
            except KeyError:
                break

            sleep(5)



class CPUPercentConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get(
                'http://127.0.0.1:19999/api/v1/data?chart=system.cpu&{}'.format(self.scope['query_string'].decode()))

            # Avoid sending data after closing websocket
            try:
                self.send_json(json.loads(response.content.decode()))
            except KeyError:
                break

            sleep(5)


class RAMConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get(
                'http://127.0.0.1:19999/api/v1/data?chart=system.ram&{}'.format(self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(5)


class SystemIOConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get(
                'http://127.0.0.1:19999/api/v1/data?chart=system.io&{}'.format(self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class NetworkConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get(
                'http://127.0.0.1:19999/api/v1/data?chart=system.ipv4&{}'.format(self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(5)


class DiskIOConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=disk_inodes._&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(30)


class DiskUsageConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=disk_space._&{}'.format(
                self.scope['query_string'].decode()))  # TODO: /var
            self.send_json(json.loads(response.content.decode()))
            sleep(30)


class InterruptsConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=system.interrupts&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class SoftirqsConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=system.softirqs&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class SoftnetConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=system.softnet_stats&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class UptimeConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=system.uptime&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class PacketsConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=ipv4.packets&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class ErrorPacketsConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=ipv4.inerrors&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class TCPConnectionsConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=ipv4.tcpsock&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class TCPPacketsConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=ipv4.tcppackets&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class UDPSocketsConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=ipv4.sockstat_udp_sockets&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class UDPPacketsConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=ipv4.udppackets&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class FirewallConsumer(JsonWebsocketConsumer):
    run_loop = False

    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return

        self.accept()
        event = {'type': 'send_data'}
        self.run_loop = True
        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def disconnect(self, close_code):
        print('close :))')
        self.run_loop = False

    def send_data(self, event):
        while self.run_loop:
            response = requests.get('http://127.0.0.1:19999/api/v1/data?chart=netfilter.conntrack_sockets&{}'.format(
                self.scope['query_string'].decode()))
            self.send_json(json.loads(response.content.decode()))
            sleep(10)


class SystemInfoConsumers(JsonWebsocketConsumer):
    def connect(self):
        if 'user' not in self.scope:
            self.close(403)
            return
        self.accept()
        event = {'type': 'send_data'}

        t = Thread(target=self.send_data, args=(event,))
        t.start()

    def send_data(self, event):

        result = dict()
        system_info = []

        for item in ['hostname', 'uptime', 'servertime', 'timezone','last_login_ip', 'last_login_time',
                         'serial_number', 'token_number',
                         'release_version', 'module_list']:

            key = dict()
            key_str = item
            key['display_name'] = key_str.replace('hostname', 'Host Name').replace('release_version', 'Release Version')\
                .replace('serial_number', 'Serial Number') .replace('servertime', 'Server Time').replace('uptime', 'Uptime')\
                .replace('token_number', 'Token Number').replace('timezone', 'Timezone').replace('last_login_ip', 'Last Login IP')\
                .replace('last_login_time', 'Last Login Time')

            key['value'] = getattr(SystemInfo, 'get_{}'.format(item))()
            key['key'] = item
            system_info.append(key)
            result['system_info'] = system_info
            self.send_json(result)