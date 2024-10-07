import datetime

import pymongo
from pymongo import MongoClient
from pymongo.errors import ExecutionTimeout
from rest_framework import views, serializers
from rest_framework.response import Response

from logging_app.serializers import LogSerializer
from utils.utils import run_thread

MAX_TIME = 30000


def calculate_nex_prev(request, src, count):
    try:
        limit = int(request.query_params.get('limit', None))
        offset = int(request.query_params.get('offset', None))
        absolute_uri = request.build_absolute_uri('/api/log?{}'.format(src))
        if offset == 0:  # first page
            previous = None
            if limit >= count:  # last page
                next = None
            else:  # we have other pages
                next = "{}?limit={}&offset={}".format(absolute_uri, limit, offset + limit)
        else:
            if offset - limit >= 0:
                previous = "{}?limit={}&offset={}".format(absolute_uri, limit, offset - limit)
            else:
                previous = None
            if offset + limit >= count:  # last page
                next = None
            else:
                next = "{}?limit={}&offset={}".format(absolute_uri, limit, offset + limit)
    except Exception:
        previous = None
        next = None
    return previous, next


class GeneralLogView(views.APIView):
    serializer_class = LogSerializer
    http_method_names = ['get']
    flag = 'none'
    queryset = None
    cursor = None
    execution_time = 0
    count = 0
    next = None
    previous = None
    data = dict()

    def get(self, request):
        try:
            if GeneralLogView.flag == 'loaded':
                GeneralLogView.flag = 'none'
                data = [
                    {"count": GeneralLogView.count, "next": GeneralLogView.next, "previous": GeneralLogView.previous,
                     "results": GeneralLogView.queryset}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            elif GeneralLogView.flag == 'timeout':
                GeneralLogView.flag = 'none'
                data = [{"count": 0, "next": None, "previous": None,
                         "results": [{"message": "timeout", "timestamp": "", "_id": ""}]}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            elif GeneralLogView.flag == 'failed':
                GeneralLogView.flag = 'none'
                raise serializers.ValidationError('failed')

            elif GeneralLogView.flag == 'loading':
                data = [{"count": 0, "next": None, "previous": None,
                         "results": [{"message": "pending", "timestamp": "", "_id": ""}]}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            GeneralLogView.flag = 'loading'
            GeneralLogView.queryset = None
            run_thread(target=self.run_search, name='run_search', args=())
            data = [{"count": 0, "next": None, "previous": None,
                     "results": [{"message": "pending", "timestamp": "", "_id": ""}]}]
            results = LogSerializer(data, many=True).data
            return Response(results[0])

        except Exception:
            GeneralLogView.flag = 'failed'
            raise serializers.ValidationError('failed')

    def run_search(self):
        try:
            request_limit = self.request.query_params.get('limit', None)
            request_offset = self.request.query_params.get('offset', None)
            search = self.request.query_params.get('search', '')
            sender = self.request.query_params.get('sender', None)
            message = self.request.query_params.get('message', '')
            from_timestamp = self.request.query_params.get('from_timestamp', None)
            to_timestamp = self.request.query_params.get('to_timestamp', None)
            ordering_field = self.request.query_params.get('ordering', None)

            client = MongoClient()
            db = client['log']
            collection = db['general_log']
            GeneralLogView.queryset = collection.find().sort('$natural', pymongo.DESCENDING).skip(
                int(request_offset)).limit(
                int(request_limit)).max_time_ms(
                MAX_TIME)
            query = {}

            if search or message:
                query["$and"] = [{'message': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                 {'message': {'$regex': '.*{}.*'.format(message), '$options': 'i'}}]
            if sender:
                query['sender'] = {"$regex": ".*{}.*".format(sender), '$options': 'i'}

            if from_timestamp and to_timestamp:
                from_time = datetime.datetime(int(from_timestamp.split('/')[0]),
                                              int(from_timestamp.split('/')[1]),
                                              int(from_timestamp.split('/')[2]))
                to_time = datetime.datetime(int(to_timestamp.split('/')[0]),
                                            int(to_timestamp.split('/')[1]),
                                            int(to_timestamp.split('/')[2]))
                query['timestamp'] = {"$lte": to_time, "$gte": from_time}
            elif to_timestamp:
                to_time = datetime.datetime(int(to_timestamp.split('/')[0]),
                                            int(to_timestamp.split('/')[1]),
                                            int(to_timestamp.split('/')[2]))
                query['timestamp'] = {"$lte": to_time}
            elif from_timestamp:
                from_time = datetime.datetime(int(from_timestamp.split('/')[0]),
                                              int(from_timestamp.split('/')[1]),
                                              int(from_timestamp.split('/')[2]))
                query['timestamp'] = {"$gte": from_time}

            if not ordering_field:
                GeneralLogView.cursor = collection.find(query).sort('$natural', pymongo.DESCENDING).skip(
                    int(request_offset)).limit(
                    int(request_limit)).max_time_ms(MAX_TIME)
            else:
                if ordering_field[0] == '-':
                    GeneralLogView.cursor = collection.find(query).sort(ordering_field[1:], pymongo.DESCENDING).skip(
                        int(request_offset)).limit(
                        int(request_limit)).max_time_ms(MAX_TIME)
                else:
                    GeneralLogView.cursor = collection.find(query).sort(ordering_field, pymongo.ASCENDING).skip(
                        int(request_offset)).limit(
                        int(request_limit)).max_time_ms(MAX_TIME)

            try:
                self.fetch_data()
                GeneralLogView.previous, GeneralLogView.next = calculate_nex_prev(self.request, 'vpn-logs',
                                                                                  GeneralLogView.count)
                GeneralLogView.flag = 'loaded'
            except pymongo.errors.ExecutionTimeout:
                del GeneralLogView.queryset
                GeneralLogView.flag = 'timeout'
        except Exception:
            del GeneralLogView.queryset
            GeneralLogView.flag = 'failed'

    def fetch_data(self):
        import time
        start_time = time.time()
        if GeneralLogView.cursor:
            GeneralLogView.count = GeneralLogView.cursor.count()
            GeneralLogView.queryset = list(GeneralLogView.cursor)
        end_time = time.time()
        GeneralLogView.execution_time = max(end_time - start_time, 0)


class AdminLogView(views.APIView):
    serializer_class = LogSerializer
    http_method_names = ['get']
    flag = 'none'
    queryset = None
    cursor = None
    execution_time = 0
    count = 0
    next = None
    previous = None
    data = dict()

    def get(self, request):
        try:
            if AdminLogView.flag == 'loaded':
                AdminLogView.flag = 'none'
                data = [{"count": AdminLogView.count, "next": AdminLogView.next, "previous": AdminLogView.previous,
                         "results": AdminLogView.queryset}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            elif AdminLogView.flag == 'timeout':
                AdminLogView.flag = 'none'
                data = [{"count": 0, "next": None, "previous": None,
                         "results": [{"message": "timeout", "timestamp": "", "_id": ""}]}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            elif AdminLogView.flag == 'failed':
                AdminLogView.flag = 'none'
                raise serializers.ValidationError('failed')

            elif AdminLogView.flag == 'loading':
                data = [{"count": 0, "next": None, "previous": None,
                         "results": [{"message": "pending", "timestamp": "", "_id": ""}]}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            AdminLogView.flag = 'loading'
            AdminLogView.queryset = None
            run_thread(target=self.run_search, name='run_search', args=())
            data = [{"count": 0, "next": None, "previous": None,
                     "results": [{"message": "pending", "timestamp": "", "_id": ""}]}]
            results = LogSerializer(data, many=True).data
            return Response(results[0])

        except Exception:
            AdminLogView.flag = 'failed'
            raise serializers.ValidationError('failed')

    def run_search(self):
        try:
            request_limit = self.request.query_params.get('limit', None)
            request_offset = self.request.query_params.get('offset', None)
            user = self.request.query_params.get('user', None)
            search = self.request.query_params.get('search', '')
            message = self.request.query_params.get('message', '')
            details = self.request.query_params.get('details', None)
            ip = self.request.query_params.get('ip', None)
            operation = self.request.query_params.get('operation', None)
            from_timestamp = self.request.query_params.get('from_timestamp', None)
            to_timestamp = self.request.query_params.get('to_timestamp', None)
            ordering_field = self.request.query_params.get('ordering', None)

            client = MongoClient()
            db = client['log']
            collection = db['admin_log']
            AdminLogView.queryset = collection.find().sort('$natural', pymongo.DESCENDING).skip(
                int(request_offset)).limit(
                int(request_limit)).max_time_ms(
                MAX_TIME)
            query = {}

            if search or message:
                query["$and"] = [{'message': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                 {'message': {'$regex': '.*{}.*'.format(message), '$options': 'i'}}]
            if user:
                query['user'] = {"$regex": ".*{}.*".format(user), '$options': 'i'}

            if details:
                query['details'] = {"$regex": ".*{}.*".format(details), '$options': 'i'}
            if ip:
                query['ip'] = {"$regex": ".*{}.*".format(ip)}
            if operation:
                query['operation'] = {"$regex": ".*{}.*".format(operation), '$options': 'i'}

            if from_timestamp and to_timestamp:
                from_time = datetime.datetime(int(from_timestamp.split('/')[0]),
                                              int(from_timestamp.split('/')[1]),
                                              int(from_timestamp.split('/')[2]))
                to_time = datetime.datetime(int(to_timestamp.split('/')[0]),
                                            int(to_timestamp.split('/')[1]),
                                            int(to_timestamp.split('/')[2]))
                query['timestamp'] = {"$lte": to_time, "$gte": from_time}
            elif to_timestamp:
                to_time = datetime.datetime(int(to_timestamp.split('/')[0]),
                                            int(to_timestamp.split('/')[1]),
                                            int(to_timestamp.split('/')[2]))
                query['timestamp'] = {"$lte": to_time}
            elif from_timestamp:
                from_time = datetime.datetime(int(from_timestamp.split('/')[0]),
                                              int(from_timestamp.split('/')[1]),
                                              int(from_timestamp.split('/')[2]))
                query['timestamp'] = {"$gte": from_time}

            if not ordering_field:
                AdminLogView.cursor = collection.find(query).sort('$natural', pymongo.DESCENDING).skip(
                    int(request_offset)).limit(
                    int(request_limit)).max_time_ms(MAX_TIME)
            else:
                if ordering_field[0] == '-':
                    AdminLogView.cursor = collection.find(query).sort(ordering_field[1:], pymongo.DESCENDING).skip(
                        int(request_offset)).limit(
                        int(request_limit)).max_time_ms(MAX_TIME)
                else:
                    AdminLogView.cursor = collection.find(query).sort(ordering_field, pymongo.ASCENDING).skip(
                        int(request_offset)).limit(
                        int(request_limit)).max_time_ms(MAX_TIME)
            try:
                self.fetch_data()
                AdminLogView.previous, AdminLogView.next = calculate_nex_prev(self.request, 'admin-logs',
                                                                              AdminLogView.count)
                AdminLogView.flag = 'loaded'
            except pymongo.errors.ExecutionTimeout:
                del AdminLogView.queryset
                AdminLogView.flag = 'timeout'
        except Exception:
            del AdminLogView.queryset
            AdminLogView.flag = 'failed'

    def fetch_data(self):
        import time
        start_time = time.time()
        if AdminLogView.cursor:
            AdminLogView.count = AdminLogView.cursor.count()
            AdminLogView.queryset = list(AdminLogView.cursor)
        end_time = time.time()
        AdminLogView.execution_time = max(end_time - start_time, 0)


class FirewallLogView(views.APIView):
    serializer_class = LogSerializer
    http_method_names = ['get']
    flag = 'none'
    queryset = None
    cursor = None
    execution_time = 0
    count = 0
    next = None
    previous = None
    data = dict()

    def get(self, request):
        try:
            if FirewallLogView.flag == 'loaded':
                FirewallLogView.flag = 'none'
                data = [
                    {"count": FirewallLogView.count, "next": FirewallLogView.next, "previous": FirewallLogView.previous,
                     "results": FirewallLogView.queryset}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            elif FirewallLogView.flag == 'timeout':
                FirewallLogView.flag = 'none'
                data = [{"count": 0, "next": None, "previous": None,
                         "results": [{"message": "timeout", "timestamp": "", "_id": ""}]}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            elif FirewallLogView.flag == 'failed':
                FirewallLogView.flag = 'none'
                raise serializers.ValidationError('failed')

            elif FirewallLogView.flag == 'loading':
                data = [{"count": 0, "next": None, "previous": None,
                         "results": [{"message": "pending", "timestamp": "", "_id": ""}]}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            FirewallLogView.flag = 'loading'
            FirewallLogView.queryset = None
            run_thread(target=self.run_search, name='run_search', args=())
            data = [{"count": 0, "next": None, "previous": None,
                     "results": [{"message": "pending", "timestamp": "", "_id": ""}]}]
            results = LogSerializer(data, many=True).data
            return Response(results[0])

        except Exception as e:
            FirewallLogView.flag = 'failed'
            raise serializers.ValidationError('failed')

    def run_search(self):
        try:
            request_limit = self.request.query_params.get('limit', None)
            request_offset = self.request.query_params.get('offset', None)
            search = self.request.query_params.get('search', None)
            dst_mac = self.request.query_params.get('dst_mac', None)
            protocol = self.request.query_params.get('protocol', None)
            action = self.request.query_params.get('action', None)
            from_timestamp = self.request.query_params.get('from_timestamp', None)
            to_timestamp = self.request.query_params.get('to_timestamp', None)
            input_interface = self.request.query_params.get('input_interface', None)
            l7_app = self.request.query_params.get('l7_app', None)
            output_interface = self.request.query_params.get('output_interface', None)
            src_ip = self.request.query_params.get('src_ip', None)
            user = self.request.query_params.get('user', None)
            dst_ip = self.request.query_params.get('dst_ip', None)
            dst_port = self.request.query_params.get('dst_port', None)
            src_port = self.request.query_params.get('src_port', None)
            src_mac = self.request.query_params.get('src_mac', None)
            policy_id = self.request.query_params.get('policy_id', None)
            policy_name = self.request.query_params.get('policy_name', None)
            ordering_field = self.request.query_params.get('ordering', None)

            client = MongoClient()
            db = client['log']
            collection = db['firewall_log']
            FirewallLogView.queryset = collection.find().sort('$natural', pymongo.DESCENDING).skip(
                int(request_offset)).limit(
                int(request_limit)).max_time_ms(
                MAX_TIME)
            query = {}

            if search:
                query["$or"] = [{'dst_mac': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'protocol': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'action': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'input_interface': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'l7_app': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'output_interface': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'src_ip': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'user': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'dst_ip': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'dst_port': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'src_port': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'src_mac': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                {'policy_name': {'$regex': '.*{}.*'.format(search), '$options': 'i'}}]
            if dst_mac:
                query['dst_mac'] = {"$regex": ".*{}.*".format(dst_mac), '$options': 'i'}
            if protocol:
                query['protocol'] = {"$regex": ".*{}.*".format(protocol), '$options': 'i'}
            if action:
                query['action'] = {"$regex": ".*{}.*".format(action), '$options': 'i'}
            if from_timestamp and to_timestamp:
                from_time = datetime.datetime(int(from_timestamp.split('/')[0]),
                                              int(from_timestamp.split('/')[1]),
                                              int(from_timestamp.split('/')[2]))
                to_time = datetime.datetime(int(to_timestamp.split('/')[0]),
                                            int(to_timestamp.split('/')[1]),
                                            int(to_timestamp.split('/')[2]))
                query['timestamp'] = {"$lte": to_time, "$gte": from_time}
            elif to_timestamp:
                to_time = datetime.datetime(int(to_timestamp.split('/')[0]),
                                            int(to_timestamp.split('/')[1]),
                                            int(to_timestamp.split('/')[2]))
                query['timestamp'] = {"$lte": to_time}
            elif from_timestamp:
                from_time = datetime.datetime(int(from_timestamp.split('/')[0]),
                                              int(from_timestamp.split('/')[1]),
                                              int(from_timestamp.split('/')[2]))
                query['timestamp'] = {"$gte": from_time}
            if input_interface:
                query['input_interface'] = {"$regex": ".*{}.*".format(input_interface), '$options': 'i'}
            if l7_app:
                query['l7_app'] = {"$regex": ".*{}.*".format(l7_app), '$options': 'i'}
            if output_interface:
                query['output_interface'] = {"$regex": ".*{}.*".format(output_interface), '$options': 'i'}
            if src_ip:
                query['src_ip'] = {"$regex": ".*{}.*".format(src_ip)}
            if user:
                query['user'] = {"$regex": ".*{}.*".format(user), '$options': 'i'}
            if dst_ip:
                query['dst_ip'] = {"$regex": ".*{}.*".format(dst_ip)}
            if dst_port:
                query['dst_port'] = {"$regex": ".*{}.*".format(dst_port)}
            if src_port:
                query['src_port'] = {"$regex": ".*{}.*".format(src_port)}
            if src_mac:
                query['src_mac'] = {"$regex": ".*{}.*".format(src_mac), '$options': 'i'}
            if policy_id:
                query['policy_id'] = {"$regex": ".*{}.*".format(policy_id)}
            if policy_name:
                query['policy_name'] = {"$regex": ".*{}.*".format(policy_name), '$options': 'i'}

            if not ordering_field:
                FirewallLogView.cursor = collection.find(query).sort('$natural', pymongo.DESCENDING).skip(
                    int(request_offset)).limit(
                    int(request_limit)).max_time_ms(MAX_TIME)
            else:
                if ordering_field[0] == '-':
                    FirewallLogView.cursor = collection.find(query).sort(ordering_field[1:], pymongo.DESCENDING).skip(
                        int(request_offset)).limit(
                        int(request_limit)).max_time_ms(MAX_TIME)
                else:
                    FirewallLogView.cursor = collection.find(query).sort(ordering_field, pymongo.ASCENDING).skip(
                        int(request_offset)).limit(
                        int(request_limit)).max_time_ms(MAX_TIME)
            try:
                self.fetch_data()
                FirewallLogView.previous, FirewallLogView.next = calculate_nex_prev(self.request, 'firewall-logs',
                                                                                    FirewallLogView.count)
                FirewallLogView.flag = 'loaded'
            except pymongo.errors.ExecutionTimeout:
                del FirewallLogView.queryset
                FirewallLogView.flag = 'timeout'
        except Exception:
            del FirewallLogView.queryset
            FirewallLogView.flag = 'failed'

    def fetch_data(self):
        import time
        start_time = time.time()
        if FirewallLogView.cursor:
            FirewallLogView.count = FirewallLogView.cursor.count()
            FirewallLogView.queryset = list(FirewallLogView.cursor)
        end_time = time.time()
        FirewallLogView.execution_time = max(end_time - start_time, 0)


class VPNLogView(views.APIView):
    serializer_class = LogSerializer
    http_method_names = ['get']
    flag = 'none'
    queryset = None
    cursor = None
    execution_time = 0
    count = 0
    next = None
    previous = None
    data = dict()

    def get(self, request):
        try:
            if VPNLogView.flag == 'loaded':
                VPNLogView.flag = 'none'
                data = [{"count": VPNLogView.count, "next": VPNLogView.next, "previous": VPNLogView.previous,
                         "results": VPNLogView.queryset}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            elif VPNLogView.flag == 'timeout':
                VPNLogView.flag = 'none'
                data = [{"count": 0, "next": None, "previous": None,
                         "results": [{"message": "timeout", "timestamp": "", "_id": ""}]}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            elif VPNLogView.flag == 'failed':
                VPNLogView.flag = 'none'
                raise serializers.ValidationError('failed')

            elif VPNLogView.flag == 'loading':
                data = [{"count": 0, "next": None, "previous": None,
                         "results": [{"message": "pending", "timestamp": "", "_id": ""}]}]
                results = LogSerializer(data, many=True).data
                return Response(results[0])

            VPNLogView.flag = 'loading'
            VPNLogView.queryset = None
            run_thread(target=self.run_search, name='run_search', args=())
            data = [{"count": 0, "next": None, "previous": None,
                     "results": [{"message": "pending", "timestamp": "", "_id": ""}]}]
            results = LogSerializer(data, many=True).data
            return Response(results[0])

        except Exception as e:
            VPNLogView.flag = 'failed'
            raise serializers.ValidationError('failed')

    def run_search(self):
        try:
            request_limit = self.request.query_params.get('limit', None)
            request_offset = self.request.query_params.get('offset', None)
            search = self.request.query_params.get('search', '')
            message = self.request.query_params.get('message', '')
            from_timestamp = self.request.query_params.get('from_timestamp', None)
            to_timestamp = self.request.query_params.get('to_timestamp', None)
            ordering_field = self.request.query_params.get('ordering', None)

            client = MongoClient()
            db = client['log']
            collection = db['vpn_log']
            VPNLogView.queryset = collection.find().sort('$natural', pymongo.DESCENDING).skip(
                int(request_offset)).limit(
                int(request_limit)).max_time_ms(
                MAX_TIME)
            query = {}
            if search or message:
                query["$and"] = [{'message': {'$regex': '.*{}.*'.format(search), '$options': 'i'}},
                                 {'message': {'$regex': '.*{}.*'.format(message), '$options': 'i'}}]
                # query['message'] = {"$regex": ".*{}.*".format(search)}
            if from_timestamp and to_timestamp:
                from_time = datetime.datetime(int(from_timestamp.split('/')[0]),
                                              int(from_timestamp.split('/')[1]),
                                              int(from_timestamp.split('/')[2]))
                to_time = datetime.datetime(int(to_timestamp.split('/')[0]),
                                            int(to_timestamp.split('/')[1]),
                                            int(to_timestamp.split('/')[2]))
                query['timestamp'] = {"$lte": to_time, "$gte": from_time}
            elif to_timestamp:
                to_time = datetime.datetime(int(to_timestamp.split('/')[0]),
                                            int(to_timestamp.split('/')[1]),
                                            int(to_timestamp.split('/')[2]))
                query['timestamp'] = {"$lte": to_time}
            elif from_timestamp:
                from_time = datetime.datetime(int(from_timestamp.split('/')[0]),
                                              int(from_timestamp.split('/')[1]),
                                              int(from_timestamp.split('/')[2]))
                query['timestamp'] = {"$gte": from_time}

            if not ordering_field:
                VPNLogView.cursor = collection.find(query).sort('$natural', pymongo.DESCENDING).skip(
                    int(request_offset)).limit(
                    int(request_limit)).max_time_ms(MAX_TIME)
            else:
                if ordering_field[0] == '-':
                    VPNLogView.cursor = collection.find(query).sort(ordering_field[1:], pymongo.DESCENDING).skip(
                        int(request_offset)).limit(
                        int(request_limit)).max_time_ms(MAX_TIME)
                else:
                    VPNLogView.cursor = collection.find(query).sort(ordering_field, pymongo.ASCENDING).skip(
                        int(request_offset)).limit(
                        int(request_limit)).max_time_ms(MAX_TIME)
            try:
                self.fetch_data()
                VPNLogView.previous, VPNLogView.next = calculate_nex_prev(self.request, 'vpn-logs', VPNLogView.count)
                VPNLogView.flag = 'loaded'
            except pymongo.errors.ExecutionTimeout:
                del VPNLogView.queryset
                VPNLogView.flag = 'timeout'
        except Exception as e:
            del VPNLogView.queryset
            VPNLogView.flag = 'failed'

    def fetch_data(self):
        import time
        start_time = time.time()
        if VPNLogView.cursor:
            VPNLogView.count = VPNLogView.cursor.count()
            VPNLogView.queryset = list(VPNLogView.cursor)
        end_time = time.time()
        VPNLogView.execution_time = max(end_time - start_time, 0)
