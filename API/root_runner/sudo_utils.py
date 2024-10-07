import os
import subprocess
import sys
from datetime import datetime

import requests
import requests_unixsocket
from django.core.management import call_command
from rest_framework.response import Response

from api.settings import BACKUP_DIR
from brand import BRAND
from root_runner.utils import command_runner, file_reader, check_path_exists
from utils.config_files import TEST_PATH, TEST_COMMANDS_FILE, API_PATH, RC_LOCAL_FILE
from utils.log import log

HOST = '127.0.0.1'
PORT = 8888


def sudo_runner(cmd, wait_for_output=True):
    session = requests_unixsocket.Session()
    if 'test' in sys.argv:
        if cmd.startswith('ip route add'):
            command_runner('touch {}/route.txt'.format(TEST_PATH))
            command_runner('echo {} >> {}/route.txt'.format(cmd.split('ip route add')[1].strip(), TEST_PATH))

        elif cmd.startswith('ip route del'):
            command_runner('touch {}/route.txt'.format(TEST_PATH))
            with open('{}/route.txt'.format(TEST_PATH), 'r') as test_route_file:
                content = test_route_file.read()

            with open('{}/route.txt'.format(TEST_PATH), 'w') as test_route_file:
                content = content.replace(cmd.split('ip route del')[1].strip(), '')
                test_route_file.write(content)
        command_runner('mkdir -p {}/  > /dev/null 2>&1'.format(TEST_PATH))
        command_runner('touch {}{}'.format(TEST_PATH, TEST_COMMANDS_FILE))
        command_runner("echo '{}' >> {}{}".format(cmd, TEST_PATH, TEST_COMMANDS_FILE))
        return True, 'done'
    try:
        data = {
            'cmd': cmd,
            'wait_for_output': wait_for_output
        }
        result = session.post('http+unix://%2Ftmp%2Froot_runner.sock/run_command', data=data)
    except requests.exceptions.ConnectionError as e:
        return False, "Request timeout in root_runner"

    if result.status_code == 200:
        status = True
    else:
        status = False

    return status, result.content.decode()


def sudo_file_writer(file, content, mode):
    if 'test' in sys.argv:
        directory = '/'.join(file.split('/')[:-1])
        command_runner('mkdir -p {}{}'.format(TEST_PATH, directory))

        with open('{}{}'.format(TEST_PATH, file), mode) as f:
            f.write(content)

        return True, 'done'

    data = {
        'file': file,
        'content': content,
        'mode': mode
    }
    session = requests_unixsocket.Session()
    result = session.post('http+unix://%2Ftmp%2Froot_runner.sock/write_file', data=data)
    if result.status_code == 200:
        status = True
    else:
        status = False

    return status, result.content.decode()


def sudo_file_reader(file):
    if 'test' in sys.argv:
        file_path = TEST_PATH + file
        command_runner(
            'mkdir -p "{}" && touch "{}"'.format(file_path.replace(file_path.split('/').pop(), ''), file_path))
        content = file_reader('{}'.format(file_path))

        return True, content

    data = {
        'file': file
    }
    session = requests_unixsocket.Session()
    result = session.post('http+unix://%2Ftmp%2Froot_runner.sock/read_file', data=data)
    if result.status_code == 200:
        status = True
    else:
        status = False

    return status, result.content.decode()


def sudo_check_path_exists(path):
    if 'test' in sys.argv:
        result = check_path_exists('{}{}'.format(TEST_PATH, path))
        return True, str(result)

    data = {
        'path': path
    }
    session = requests_unixsocket.Session()
    result = session.post('http+unix://%2Ftmp%2Froot_runner.sock/check_path_exists', data=data)
    if result.status_code == 200:
        status = True
    else:
        status = False

    return status, result.content.decode()


def sudo_mkdir(path):
    if 'test' in sys.argv:
        directory = '/'.join(path.split('/')[:-1])
        command_runner('mkdir -p {}{}'.format(TEST_PATH, directory))
        return True, 'done'

    data = {
        'path': path
    }
    session = requests_unixsocket.Session()
    result = session.post('http+unix://%2Ftmp%2Froot_runner.sock/mkdir', data=data)
    if result.status_code == 200:
        status = True
    else:
        status = False

    return status, result.content.decode()


def sudo_remove_directory(path):
    if 'test' in sys.argv:
        directory = '/'.join(path.split('/')[:-1])
        command_runner('rm -rf {}{}'.format(TEST_PATH, directory))
        return True, 'done'

    data = {
        'path': path
    }
    session = requests_unixsocket.Session()
    result = session.post('http+unix://%2Ftmp%2Froot_runner.sock/remove_dir', data=data)
    if result.status_code == 200:
        status = True
    else:
        status = False

    return status, result.content.decode()


# def sudo_install_update(path):
#     from config_app.models import Update
#
#     if 'test' in sys.argv:
#         s, o = install_update(path)
#         return s, o
#
#     data = {
#         'path': path
#     }
#     session = requests_unixsocket.Session()
#     result = session.post('http+unix://%2Ftmp%2Froot_runner.sock/update', data=data)
#     print(result.content)
#     if result.status_code == 200:
#         status = True
#         update = Update.objects.get(status='installing')
#         update.status = 'completed'
#         update.save()
#     else:
#         status = False
#
#     return status, result.content.decode()


def sudo_pam_authenticate(username, password):
    data = {
        'username': username,
        'password': password
    }
    session = requests_unixsocket.Session()
    result = session.post('http+unix://%2Ftmp%2Froot_runner.sock/authenticate', data=data)
    if result.status_code == 400:
        status = False
    else:
        status = True

    return status


def sudo_restart_systemd_service(service):
    session = requests_unixsocket.Session()
    if 'test' in sys.argv:
        return True, 'done'

    try:
        data = {
            'service': service
        }
        result = session.post('http+unix://%2Ftmp%2Froot_runner.sock/restart_systemd_service', data=data)
    except requests.exceptions.ConnectionError:
        return False, "Request timeout in root_runner"

    if result.status_code == 200:
        status = True
    else:
        status = False

    return status, result.content.decode()


def sudo_install_update(path, username, ip):
    from config_app.models import Update
    update = Update.objects.get(status='restore_point')
    command_runner('rm {}/update_temp -r'.format(BACKUP_DIR))
    command_runner('mkdir -p {}update_temp'.format(BACKUP_DIR))
    now = datetime.now()

    try:
        status, content = sudo_file_reader(RC_LOCAL_FILE)
        if not status:
            raise Exception(content)

        content = content.replace('rollback=0', 'rollback=1')
        sudo_file_writer(RC_LOCAL_FILE, content, 'w')
    except:
        pass

    try:
        call_command('dumpdata', exclude=[
            'auth_app.AdminLoginLock',
            'auth_app.Token',
            'sessions.Session',
            'auth.permission',
            'contenttypes'
            # 'silk'
        ], output='/var/ngfw/update_temp/restore_point{}.json'.format(now))

    except Exception as e:
        print(str(e))
        raise e

    command_runner(
        'tar -cf /var/ngfw/update_temp/restore_point.tar {} '.format(API_PATH))

    command_runner(
        'tar -uvf /var/ngfw/update_temp/restore_point.tar  /var/ngfw/')

    log('config', 'updates', 'restore point', 'success',
        username, ip)


    s, o = command_runner('tar xvf {} -C /var/ngfw --overwrite'.format(path))
    if not s:
        return s, o

    print(o)
    s, o = sudo_runner("echo 'ngfw:ngfw' | chpasswd")
    if not s:
        raise Exception(o)
    print(o)
    s, o = sudo_runner("sed -i '/ngfw/d' /etc/sudoers")

    if not s:
        raise Exception(o)
    print(o)

    command_runner("echo '{1}' > {0}update_info.txt".format(BACKUP_DIR,
                                                            datetime.now()

                                                            ))

    o, total_step_of_installing = command_runner(
        "find /var/ngfw/ -iname '*.yml' -print0 | xargs -0 grep --color -r -P '^\s*- name: ' | wc -l")
    step_of_installing_update = 0
    update.status = 'installing'
    update.install_progress = 0
    update.save()
    log('config', 'updates', 'install', 'success',
        username, ip)

    cmd = 'ansible-playbook /var/ngfw/install.yml -b --become-user root --extra-vars "ansible_sudo_pass=ngfw" -u ngfw ' \
          '-c local '
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    for line in process.stdout:
        sys.stdout.write(line.decode())
        templog = str(line.decode())
        command_runner("echo '{1}' >> {0}update_info.txt".format(BACKUP_DIR, templog))

        if int(total_step_of_installing) > step_of_installing_update:
            update.install_progress = int((step_of_installing_update / int(total_step_of_installing)) * 100)
            update.save()
        else:
            update.install_progress = 99
            update.save()

        if 'TASK' in templog:
            step_of_installing_update += 1

    command_runner('tar -uvf {0}/update_temp/restore_point.tar {0}update_info.txt'.format(BACKUP_DIR))

    s, version = command_runner("cat {} | grep ReleaseID_id | cut -d' ' -f2".format(
        os.path.join(BACKUP_DIR, 'currentversion.yml'))
    )

    if update.version == version:

        update.install_progress = 100
        update.status = 'completed'
        update.save()
        sudo_runner('rm /var/ngfw/install.yml')
        sudo_runner('rm /var/ngfw/roles -r')

        try:
            status, content = sudo_file_reader(RC_LOCAL_FILE)
            if not status:
                raise Exception(content)

            content = content.replace('rollback=1', 'rollback=0')
            sudo_file_writer(RC_LOCAL_FILE, content, 'w')
        except:
            pass

        log('config', 'updates', 'install', 'finish',
            username, ip)
        sudo_runner('find /var/ngfw/{brand}.v*tar.xz* \! -wholename "{path}*" -delete'.format(brand=BRAND ,path=path))
        sudo_runner('shutdown -r +1')
        return Response('Update successfully install  ..... ')

    else:
        update.status = 'rollback'
        update.save()
        log('config', 'updates', 'rollback', 'success',
            username, ip)
        command_runner('tar xvf /var/ngfw/update_temp/restore_point.tar -C /var/ngfw/update_temp')

        # restore /var/ngfw directory
        sudo_runner('rsync -avzh /var/ngfw/update_temp/var/ngfw /var -r')

        # restore /opt directory
        sudo_runner('rsync -avzh /var/ngfw/update_temp/opt/narin /opt -r')

        # restore db
        call_command('flush', '--no-input')

        call_command('loaddata', '/var/ngfw/update_temp/restore_point{}.json'.format(now))
        sudo_runner('rm /var/ngfw/update_temp/var -r')
        sudo_runner('rm /var/ngfw/update_temp/opt -r')
        update.status = 'failed'
        update.save()

        try:
            status, content = sudo_file_reader(RC_LOCAL_FILE)
            if not status:
                raise Exception(content)

            content = content.replace('rollback=1', 'rollback=0')
            sudo_file_writer(RC_LOCAL_FILE, content, 'w')
        except:
            pass

        log('config', 'updates', 'install', 'fail',
            username, ip)
        # # delete file doesn't exist on restore point
        # sudo_runner('rsync -a --delete /var/ngfw/update_temp/opt/narin /opt -r')
        #
        # sudo_runner('rsync -a --delete /var/ngfw/update_temp/var/ngfw /var -r')

        sudo_runner('shutdown -r +1')
        return Response('Update failed restore to previous version ')