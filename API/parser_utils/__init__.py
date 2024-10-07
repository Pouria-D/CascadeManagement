import logging
import logging.handlers
from datetime import datetime

import psycopg2
import requests
from rest_framework.response import Response

from parser_utils.config import config

# Define the WSGI application object
# app = Flask(__name__)

# Configurations
# config.from_object('config')


logger = logging.getLogger('Parser')


def setLoggingConfigs(logger):
    logger.setLevel(logging.INFO)
    ch = logging.handlers.SysLogHandler(address='/dev/log',
                                        facility=logging.handlers.SysLogHandler.LOG_LOCAL0)
    # ch = logging.StreamHandler()
    ch.setLevel(logging.NOTSET)
    # create formatter
    formatter = logging.Formatter('Parser : %(levelname)s: %(message)s')
    # add formatter to ch
    ch.setFormatter(formatter)
    # add ch to logger
    logger.addHandler(ch)


setLoggingConfigs(logger)


def make_response(code, message):
    response = {'message': message, 'status_code': code}
    return Response(data=response, status=code)


def printLog(msg):
    if config['DEBUG']:
        print('\033[0;33m')
        print(msg)
        print('\033[0m')


def clear_log(_type=None, key=None, facility=None, details_type=None):
    '''
        This function sends a request to log analyzer to remove some logs.
        Parameters are attributes of logs. they will be "AND" togather.
    '''

    query = dict()
    if _type:               query['type'] = _type
    if key:                 query['key'] = key
    if facility != None:    query['facility'] = int(facility)
    if details_type:        query['details_type'] = details_type

    url = ''.join([config['LOG_ANALYZER_ADDR'], 'delete'])
    try:
        response = requests.post(url, json=query)

        if response.status_code != 200:
            logger.warning('Log Analyzer response code: %s\n Content:\n%s\n' % \
                           (response.status_code, response.content))

    except requests.exceptions.ConnectionError:
        logger.error('Can not connect to Log Analyzer.')


def send_log(log):
    '''
        This function gets a dictionary and sends it for log analyzer,
        if it does not contain timestamp or facility,
        this function adds those before sending.
    '''

    if not isinstance(log, dict):
        logger.warning("%s must be a dictionary to send for log analyzer." % log)
        return None

    if 'timestamp' not in list(log.keys()):
        log['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if 'facility' not in list(log.keys()):
        log['facility'] = 6

    if 'details' not in list(log.keys()):
        log['details'] = dict()

    url = config['LOG_ANALYZER_ADDR']
    try:
        response = requests.post(url, json=log)

        if response.status_code != 200:
            logger.warning('Log Analyzer response code: %s\n Content:\n%s\n' % \
                           (response.status_code, response.content))

    except requests.exceptions.ConnectionError:
        logger.error('Can not connect to Log Analyzer.')


# with open('/etc/freeradius/mods-available/sql') as sql_file:
#     content = sql_file.read()
#
#     username = re.search(r'^\s*login\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     host = re.search(r'^\s*server\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     password = re.search(r'^\s*password\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     port = re.search(r'^\s*port\s*=\s*(\d+)', content, re.M)
#     database_name = re.search(r'^\s*radius_db\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     authcheck_table = re.search(r'^\s*authcheck_table\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     usergroup_table = re.search(r'^\s*usergroup_table\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     groupcheck_table = re.search(r'^\s*groupcheck_table\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     acct_table = re.search(r'^\s*acct_table1\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     groupreply_table = re.search(r'^\s*groupreply_table\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#     postauth_table = re.search(r'^\s*postauth_table\s*=\s*[\'|\"](.+)[\'|\"]', content, re.M)
#
#     if username:
#         config['PostgreSQL_USERNAME'] = username.group(1)
#     else:
#         logger.error("Can't read postgresql username from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     if password:
#         config['PostgreSQL_PASSWORD'] = password.group(1)
#     else:
#         logger.error("Can't read postgresql password from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     if database_name:
#         config['PostgreSQL_DATABASE'] = database_name.group(1)
#     else:
#         logger.error("Can't read postgresql database name from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     if host:
#         config['PostgreSQL_HOST'] = host.group(1)
#     else:
#         logger.error("Can't read postgresql host address from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     if port:
#         config['PostgreSQL_PORT'] = port.group(1)
#     else:
#         logger.error("Can't read postgresql port from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     if authcheck_table:
#         config['authcheck_table'] = authcheck_table.group(1)
#     else:
#         logger.error("Can't read authcheck_table from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     if usergroup_table:
#         config['usergroup_table'] = usergroup_table.group(1)
#     else:
#         logger.error("Can't read usergroup_table from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     if groupcheck_table:
#         config['groupcheck_table'] = groupcheck_table.group(1)
#     else:
#         logger.error("Can't read groupcheck_table from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     if postauth_table:
#         config['postauth_table'] = postauth_table.group(1)
#     else:
#         logger.error("Can't read postauth_table from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     if acct_table:
#         config['acct_table'] = acct_table.group(1)
#     else:
#         logger.error("Can't read acct_table from /etc/freeradius/mods-available/sql")
#         exit(1)
#
#     if groupreply_table:
#         config['groupreply_table'] = groupreply_table.group(1)
#     else:
#         logger.error("Can't read groupreply_table from /etc/freeradius/mods-available/sql")
#         exit(1)
redis_connection = None
influx_client = None


# redis_connection = redis.StrictRedis(host=config['REDIS_HOST'], \
#                                      port=config['REDIS_PORT'], db=config['REDIS_DB'])
#
# influx_client = InfluxDBClient('localhost', 8086, 'root', 'root',
#                                config['L7_DB'])


def connect_to_db():
    con = None
    while True:
        if con and not con.closed:
            yield con

        try:
            con = psycopg2.connect(user=config['PostgreSQL_USERNAME'], \
                                   password=config['PostgreSQL_PASSWORD'], \
                                   database=config['PostgreSQL_DATABASE'], \
                                   host=config['PostgreSQL_HOST'], \
                                   port=config['PostgreSQL_PORT'])
        except Exception as e:
            logger.error("Can't connect to database. The reason:%s" % (e,))
            yield None
        else:
            yield con

# from .postgresql import PostgreSQL
# con=PostgreSQL(app).connection

# Register blueprint(s)
# from parser import mod_profile
# app.register_blueprint(mod_profile)
#
# from parser import mod_resource
# app.register_blueprint(mod_resource)
#
# from parser import mod_setting
# app.register_blueprint(mod_setting)
#
# from parser import mod_util
# app.register_blueprint(mod_util)
#
# from parser import mod_policy
# app.register_blueprint(mod_policy)
#
# from parser import mod_log
# app.register_blueprint(mod_log)
#
# from parser import mod_qos
# app.register_blueprint(mod_qos)
#
# from parser import mod_l7
# app.register_blueprint(mod_l7)
#
# from parser import mod_backup_restore
# app.register_blueprint(mod_backup_restore)
