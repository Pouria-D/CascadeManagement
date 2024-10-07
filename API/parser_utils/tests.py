# import os
# import re
# import shutil
# import unittest
# from json import dumps
#
# import psycopg2
# from psycopg2.extensions import \
#     ISOLATION_LEVEL_AUTOCOMMIT
#
# root_con = None
# configs = {}
#
#
# def init():
#     with open('config.py') as config_file:
#         config_file_content = config_file.read()
#
#     root_user = re.search(r'\s*DATABASE_ROOT_USERNAME*\s*=\s*[\'|\"](.+)[\'|\"]\s*', \
#                           config_file_content, re.M)
#     if root_user:
#         configs['root_user'] = root_user.group(1)
#
#     root_password = re.search(r'\s*DATABASE_ROOT_PASSWORD*\s*=\s*[\'|\"](.+)[\'|\"]\s*', \
#                               config_file_content, re.M)
#     if root_password:
#         configs['root_password'] = root_password.group(1)
#
#     test_db = re.search(r'\s*TEST_DATABASE_NAME*\s*=\s*[\'|\"](.+)[\'|\"]\s*', \
#                         config_file_content, re.M)
#     if test_db:
#         configs['test_db'] = test_db.group(1)
#
#     ######################################################################
#     with open('/etc/freeradius/mods-available/sql') as sql_file:
#         content = sql_file.read()
#
#     database_name = re.search(r'^\s*radius_db\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     if database_name:
#         configs['original_db_name'] = database_name.group(1)
#     else:
#         print("I can't read postgresql database name from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     username = re.search(r'^\s*login\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     if username:
#         configs['username'] = username.group(1)
#     else:
#         print("I can't read postgresql username from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     with open('/etc/freeradius/mods-available/sql', 'w') as sql_file:
#         sql_file.write(content.replace(database_name.group(), \
#                                        '\tradius_db = "%s"' % configs['test_db']))
#
#     try:
#         global root_con
#         root_con = psycopg2.connect( \
#             user=configs['root_user'], \
#             password=configs['root_password'])
#     except Exception as e:
#         print(e)
#         assert not e, "Error in creating database connection."
#
#     root_con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
#     root_cursor = root_con.cursor()
#     try:
#         root_cursor.execute("CREATE DATABASE %s OWNER %s" % \
#                             (configs['test_db'], configs['username']))
#     except Exception as e:
#         root_con.rollback()
#         print(e)
#         exit(1)
#     root_cursor.close()
#
#     #######################################################################
#     try:
#         root_con_2 = psycopg2.connect( \
#             user=configs['root_user'], \
#             password=configs['root_password'], \
#             database=configs['test_db'])
#     except Exception as e:
#         print(e)
#         assert not e, "Error in creating database connection."
#         exit(1)
#
#     root_cursor = root_con_2.cursor()
#
#     try:
#         root_cursor.execute(open("data.sql", "r").read())
#         root_con_2.commit()
#     except Exception as e:
#         print((str(e)))
#         root_con_2.rollback()
#         exit(1)
#
#     root_cursor.close()
#     root_con_2.close()
#
#
# def down():
#     global root_con
#     with open('/etc/freeradius/mods-available/sql', 'r+') as sql_conf_file:
#         content = sql_conf_file.read()
#         new_content = re.sub(r'^\s*radius_db\s*=\s*[\"|\'].*[\"|\']', \
#                              '\tradius_db = "%s"' % configs['original_db_name'], \
#                              content, flags=re.M)
#         sql_conf_file.seek(0)
#         sql_conf_file.write(new_content)
#         sql_conf_file.truncate()
#
#     root_cursor = root_con.cursor()
#
#     try:
#         root_cursor.execute("SELECT pg_terminate_backend(pid) FROM \
#             pg_stat_activity WHERE datname = '%s'" % configs['test_db'])
#         root_cursor.execute("DROP DATABASE %s" % configs['test_db'])
#     except Exception as e:
#         print((str(e)))
#         root_con.rollback()
#     root_con.close()
#
#
# class SetupClass(unittest.TestCase):
#     @classmethod
#     def setUpClass(self):
#         self.app = parser_utils.app.test_client()
#         parser_utils.app.debug = False
#         parser_utils.parser.config['TEST'] = True
#
#         self.backup_path = os.getcwd() + "/backups"
#         if not os.path.exists(self.backup_path):
#             os.makedirs(self.backup_path)
#
#         shutil.copy2('/etc/chilli/config', self.backup_path + '/config')
#         shutil.copy2('/etc/freeradius/clients.conf', self.backup_path + '/clients.conf')
#         shutil.copy2('/etc/freeradius/mods-available/sql', self.backup_path + '/sql.conf')
#
#     @classmethod
#     def tearDownClass(self):
#         shutil.copy2(self.backup_path + '/config', '/etc/chilli/config')
#         shutil.copy2(self.backup_path + '/clients.conf', '/etc/freeradius/clients.conf')
#         shutil.copy2(self.backup_path + '/sql.conf', '/etc/freeradius/mods-available/sql')
#
#         shutil.rmtree(self.backup_path)
#
#
# class Profile_Utils_Tests(SetupClass):
#     ###########################################################################
#     def test_add_user(self):
#         content = {'username': 'test_user', 'attributes': [
#             {'attribute': 'Cleartext-Password', 'value': '123'}, \
#             {'attribute': 'Login-Time', 'value': 'Th0800-1800'}], \
#                    'groups': [{'groupname': 'group1', 'priority': 2}, {'groupname': \
#                                                                            'group2', 'priority': 1}], 'mac_auth': \
#                        [{'mac': '11-22-33-44-55-10', 'force_mac_auth': True},
#                         {'mac': '11-22-33-44-55-11', 'force_mac_auth': False}]}
#
#         from parser_utils.mod_profile.utils import add_user
#         result = add_user(content)
#         assert result == 1
#
#     ###########################################################################
#     def test_delete_user(self):
#         from parser_utils.mod_profile.utils import delete_user
#         result = delete_user('a4')
#
#         assert result == 'Deleted'
#
#     ###########################################################################
#     def test_add_group(self):
#         content = {'groupname': 'group_t_add', 'attributes': [
#             {'attribute': 'Login-Time', 'value': 'Fr1400-2000'}, \
#             {'attribute': 'Max-Upload-Monthly', 'value': '5000'}
#         ]}
#         from parser_utils.mod_profile.utils import add_group
#         result = add_group(content)
#         assert result == True
#
#     ###########################################################################
#     def test_delete_group(self):
#         from parser_utils.mod_profile.utils import delete_group
#         result = delete_group('group4')
#         assert result == 1
#
#
# class Profile_View_Test(SetupClass):
#     ###########################################################################
#     def test_add_group_view(self):
#         content = {'groupname': 'group_t_add', 'attributes': [
#             {'attribute': 'Login-Time', 'value': 'Fr1400-2000'}, \
#             {'attribute': 'Max-Upload-Monthly', 'value': '5000'}
#         ]}
#
#         response = self.app.post('/profile/group/add', \
#                                  data=dumps(content), \
#                                  content_type='application/json')
#
#         assert response.status_code == 200
#
#     ###########################################################################
#     def test_update_group_view(self):
#         content = {'groupname': 'group3', 'attributes': [
#             {'attribute': 'Login-Time', 'value': 'Fr1400-2000'}, \
#             {'attribute': 'Max-Upload-Monthly', 'value': '5000'}
#         ], 'force_logout': False}
#
#         response = self.app.post('/profile/group/update', \
#                                  data=dumps(content), \
#                                  content_type='application/json')
#
#         assert response.status_code == 200
#
#     ###########################################################################
#     def test_delete_group_view(self):
#         response = self.app.post('/profile/group/delete', \
#                                  data=dumps({'groupname': 'group2'}), \
#                                  content_type='application/json')
#         assert response.status_code == 200
#
#     ###########################################################################
#     def test_add_user_view(self):
#         content = {'username': 'test_user', 'attributes': [
#             {'attribute': 'Cleartext-Password', 'value': '12345'}, \
#             {'attribute': 'Login-Time', 'value': 'Th0800-1800'}], \
#                    'groups': [{'groupname': 'group1', 'priority': 2}, {'groupname': \
#                                                                            'group2', 'priority': 1}], 'mac_auth': \
#                        [{'mac': '11-22-33-44-55-66', 'force_mac_auth': True},
#                         {'mac': '11-22-33-44-55-67', 'force_mac_auth': False}],}
#
#         response = self.app.post('/profile/user/add', \
#                                  data=dumps(content), \
#                                  content_type='application/json')
#
#         assert response.status_code == 200
#
#     ###########################################################################
#     def test_delete_user_view(self):
#         response = self.app.post('/profile/user/delete', \
#                                  data=dumps({'username': 'a2'}), \
#                                  content_type='application/json')
#
#         assert response.status_code == 200
#
#     ###########################################################################
#     def test_update_user_view(self):
#         content = {'username': 'a3', 'force_logout': False, 'attributes': [
#             {'attribute': 'Cleartext-Password', 'value': '345'}, \
#             {'attribute': 'Login-Time', 'value': 'Th0800-1800'}], \
#                    'groups': [{'groupname': 'group88', 'priority': 8}, {'groupname': \
#                                                                             'group2', 'priority': 1}], 'mac_auth': \
#                        [{'mac': '11-22-33-14-55-66', 'force_mac_auth': True}]}
#
#         response = self.app.post('/profile/user/update', \
#                                  data=dumps(content), \
#                                  content_type='application/json')
#
#         assert response.status_code == 200
#
#
# class Change_Setting_Test(SetupClass):
#     ###########################################################################
#     def test_set_shared_key(self):
#         from parser_utils.mod_setting.utils import set_shared_key
#         assert set_shared_key("1234567890"), \
#             "Error in set_shared_key! returned value = False"
#
#         with open("/etc/chilli/config") as chilli_file:
#             chilli_content = chilli_file.read()
#             assert "HS_RADSECRET='1234567890'" in chilli_content
#
#         with open('/etc/freeradius/clients.conf') as radius_configs:
#             radius_content = radius_configs.read()
#             assert "secret \t= '1234567890'" in radius_content
#
#     ###########################################################################
#     def test_database_details_radius(self):
#         test_username = "test_username"
#         test_password = "test_pssword"
#         test_port = 12345
#
#         from parser_utils.mod_setting.utils import set_database_connection_details
#         assert set_database_connection_details( \
#             test_username, test_password, test_port)
#
#         with open('/etc/freeradius/mods-available/sql') as sql_conf_file:
#             content = sql_conf_file.read()
#             assert 'login = "%s"' % test_username in content
#             assert 'password = "%s"' % test_password in content
#             assert 'port = %s' % test_port in content
#
#     ###########################################################################
#     def test_set_chilli_config(self):
#         wan = 'test_wan_if'
#         lan = 'test_lan_if'
#         hotspot_network = '120.130.140.0'
#         hotspot_netmask = '255.255.0.0'
#         listen_ip = '120.130.140.1'
#         port = 1234
#         ui_port = 4321
#         dns = '8.8.8.8'
#
#         from parser_utils.mod_setting.utils import set_chilli_configs
#         assert set_chilli_configs( \
#             wan=wan, lan=lan, hotspot_network=hotspot_network,
#             hotspot_netmask=hotspot_netmask, listen_ip=listen_ip,
#             port=port, ui_port=ui_port, dns=dns)
#
#         with open("/etc/chilli/config") as chilli_file:
#             chilli_content = chilli_file.read()
#             assert "HS_WANIF=%s" % wan in chilli_content
#             assert "HS_LANIF=%s" % lan in chilli_content
#             assert "HS_NETWORK=%s" % hotspot_network in chilli_content
#             assert "HS_NETMASK=%s" % hotspot_netmask in chilli_content
#             assert "HS_UAMLISTEN=%s" % listen_ip in chilli_content
#             assert "HS_UAMPORT=%s" % port in chilli_content
#             assert "HS_UAMUIPORT=%s" % ui_port in chilli_content
#
#     ###########################################################################
#     def test_logout(self):
#         from parser_utils.mod_util.utils import logout_user
#         assert len(logout_user("a1")) == 1
#
#     ###########################################################################
#     def test_find_group_members(self):
#         from parser_utils.mod_util.utils import group_members
#         members = group_members('group1')
#         assert members == ['a1']
#
#
# class View_Tests(SetupClass):
#     ###########################################################################
#     def test_shared_key_view_1(self):
#         response = self.app.post('/setting/sharedkey', \
#                                  data=dumps({'shared_key': 'test_key'}), \
#                                  content_type='application/json')
#         assert response.status_code == 200
#
#     ###########################################################################
#     def test_shared_key_view_2(self):
#         # test with wron key
#         response = self.app.post('/setting/sharedkey', \
#                                  data=dumps({'uncorrect_key': 'test_key'}), \
#                                  content_type='application/json')
#
#         assert response.status_code == 400
#
#     ###########################################################################
#
#     def test_logout_user_view(self):
#         response = self.app.post('/users-logout', \
#                                  data=dumps({'users': ['acct1']}), \
#                                  content_type='application/json')
#         assert response.status_code == 200
#
#     ###########################################################################
#     def test_set_database_details_view_1(self):
#         response = self.app.post('/setting/database', \
#                                  data=dumps({'username': 'test_username', 'password': \
#                                      'test_password', 'port': '5000'}), \
#                                  content_type='application/json')
#
#         assert response.status_code == 200
#
#     ###########################################################################
#     def test_set_database_details_view_2(self):
#         # test for wrong key
#         response = self.app.post('/setting/database', \
#                                  data=dumps({'wrongkey': 'test_username', 'password': \
#                                      'test_password', 'port': '5000'}), \
#                                  content_type='application/json')
#
#         assert response.status_code == 400
#
#     ###########################################################################
#     def test_add_policy(self):
#         data = {'groups': ['employees'], \
#                 'schedule': {'saturday_enable': 'False', \
#                              'monday_enable': 'False', 'schedule_to': '2017-02-28 15:00:00+00:00', \
#                              'wednesday_enable': 'False', 'tuesday_enable': 'False', \
#                              'friday_enable': 'False', 'sunday_enble': 'True', \
#                              'thursday_enable': 'False', 'schedule_from': '2017-02-28 15:00:00+00:00'}, \
#                 'src': {'src_network': [{'address_value': ['6c:f0:49:68:0e:12'], \
#                                          'address_type': 'mac'}], 'src_interfaces': ['eth0']},
#                 'users': ['admin', 'user'], \
#                 'policy_order': 100, 'services': {'l7': ['ftp', 'smtp', 'pop', 'dns', 'facebook', \
#                                                          'twitter', 'skype'],
#                                                   'l4': [{'protocol': 'TCP', 'dst_port': ['8080'], \
#                                                           'src_port': []},
#                                                          {'protocol': 'TCP', 'dst_port': ['8080'], 'src_port': []}]}, \
#                 'nat': {'DNAT_IP_range': '192.1.1.1', 'SNAT_IP_range': '192.168.10.1', \
#                         'SNAT_MASQUERADE_enabled': True, 'SNAT_port_range': '50', \
#                         'DNAT_port_range': '3100'}, 'policy_id': 200, 'dst': {'dst_network': \
#                                                                                   [{'address_value': ['192.168.100.10',
#                                                                                                       '192.168.100.100'],
#                                                                                     'address_type': \
#                                                                                         'v4'}],
#                                                                               'dst_interfaces': ['eth1']},
#                 'type': 'policy', 'log': True, 'action': 'R'}
#
#         response1 = self.app.post('/policy/add', data=dumps(data),
#                                   content_type='application/json')
#
#         assert response1.status_code == 200
#         #
#         # response2 = self.app.post('/policy/check_details', data=dumps(data),
#         #     content_type='application/json')
#         #
#         # print(response2.data)
#         # assert response2.status_code == 200
#
#     ###########################################################################
#     '''
#     def test_update_policy(self):
#         # server.POLICY_TABLE = "test_" + server.POLICY_TABLE
#         response = self.app.post('/policy/update', data=dumps({'groups': ['employees'], \
#             'schedule': {'saturday_enable': 'False', \
#             'monday_enable': 'False', 'schedule_to': '2017-02-28 15:00:00+00:00', \
#             'wednesday_enable': 'False', 'tuesday_enable': 'False', \
#             'friday_enable': 'False', 'sunday_enble': 'True', \
#             'thursday_enable': 'False', 'schedule_from': '2017-02-28 15:00:00+00:00'}, \
#             'src': {'src_network': [{'address_value': ['6c:f0:49:68:0e:12'], \
#             'address_type': 'mac'}], 'src_interfaces': ['eth0']}, 'users': ['admin', 'user'], \
#             'policy_order': 100, 'services': {'l7': ['ftp', 'smtp', 'pop', 'dns', 'facebook', \
#             'twitter', 'skype'], 'l4': [{'protocol': 'TCP', 'dst_port': ['8080'], \
#             'src_port': []}, {'protocol': 'TCP', 'dst_port': ['8080'], 'src_port': []}]}, \
#             'nat': {'DNAT_IP_range': '192.1.1.1', 'SNAT_IP_range': '192.168.10.1', \
#             'SNAT_MASQUERADE_enabled': True, 'SNAT_port_range': '50', \
#             'DNAT_port_range': '3100'}, 'policy_id': 1000, 'dst': {'dst_network': \
#             [{'address_value': ['192.168.100.10', '192.168.100.100'], 'address_type': \
#             'v4'}], 'dst_interfaces': ['eth1']}, 'type': 'policy', 'log': True, 'action': 'A'}),
#             content_type='application/json')
#         assert response.status_code == 200
#     '''
#
#     ###########################################################################
#     def test_delete_policy(self):
#         # server.POLICY_TABLE = "test_" + server.POLICY_TABLE
#         response = self.app.post('/policy/delete',
#                                  data=dumps({'policy_id': 200}),
#                                  content_type='application/json')
#         assert response.status_code == 200
#
#
# if __name__ == '__main__':
#     init()
#     import parser_utils
#
#     unittest.main(exit=False)
#     down()
