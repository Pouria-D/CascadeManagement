import os
import shutil
import subprocess
import tarfile
import threading
from time import sleep
from urllib.parse import urljoin

import requests

import parser_utils.config
from parser_utils import connect_to_db, redis_connection, logger, send_log


################################################################################

def logout_user(username):
    '''
        This function takes a username and find it's MAC with
        chilli_query (users that they are logged in) and logout them.
    '''

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()

    half_query = "SELECT callingstationid,framedipaddress FROM %s " % \
                 parser_utils.config['acct_table']
    cursor.execute(half_query + " WHERE \
        username=%s AND acctstoptime IS NULL", (username,))

    data = cursor.fetchall()

    if data:
        for row in data:
            mac = row[0]
            ip = row[1]

            logout_cmd = "sudo chilli_query logout %s" % mac
            logout_query = subprocess.Popen(logout_cmd, shell=True, stdout=subprocess.PIPE, \
                                            stderr=subprocess.STDOUT)
            logout_query.communicate()

            if logout_query.returncode == 0:
                logger.info("%s with MAC = %s logged out!" % (username, mac))

            redis_connection.delete(ip)

            log = {
                'type': 'user',
                'key': username,
                'message': 'Force logout for "%s"' % username
            }
            send_log(log)

        return data

    else:
        return None


################################################################################

def group_members(groupname):
    con = next(connect_to_db())
    if not con: return list()
    cursor = con.cursor()
    half_query = 'SELECT username from %s ' % parser_utils.config['usergroup_table']
    cursor.execute(half_query + "WHERE groupname=%s", (groupname,))
    result = cursor.fetchall()
    members = []
    for member in result:
        members.append(member[0])

    return members


################################################################################

def logout_group(groupname):
    members = group_members(groupname)
    # print(members)
    for user in members:
        logout_user(user)


################################################################################

def run_updater():
    update_resp = requests.post(urljoin(parser_utils.config['UPDATE_MANAGER'],
                                        'update'), json={'type': 'online'})
    logger.error(update_resp.text)
    if update_resp.status_code == 200:
        return True
    else:
        return False


################################################################################

def update():
    try:
        update_update_manager = requests.get(urljoin(parser_utils.config['UPDATE_MANAGER'],
                                                     'get_latest_update_manager'))
        if update_update_manager.status_code == 200:
            path = update_update_manager.json()['path']
            with tarfile.open(path) as tar_file:
                extract_path = '/tmp/extract_new_update_manager'
                if os.path.isdir(extract_path):
                    shutil.rmtree(extract_path)
                tar_file.extractall(extract_path)
                cmd = 'ansible-playbook -s %s/install.yml' % extract_path
                ansible_query = subprocess.Popen(cmd, shell=True,
                                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                output = ansible_query.communicate()[0]
                logger.debug(output)
                if ansible_query.returncode != 0:
                    msg = "Can not install new update manager."
                    logger.error(msg)
                    return False, msg
        else:
            return False, update_update_manager.json()['error']

        cmd = 'service update_manager restart'
        ps = subprocess.Popen(cmd, shell=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        ps.communicate()
        if ps.returncode != 0:
            return False, "Cant restart update manager. %s" % ps.returncode
        sleep(5)

        updater_thread = threading.Thread(target=run_updater)
        updater_thread.start()
        return True, 'OK'

    except requests.exceptions.ConnectionError:
        msg = "Can't connect to update manager"
        logger.error(msg)
        return False, msg


################################################################################

def get_updating_status():
    try:
        resp = requests.get(parser_utils.config['UPDATE_MANAGER'] + 'update_state')
        result = resp.json()['update_state']
    except Exception as e:
        logger.error(str(e))
        return False

    return bool(result)
