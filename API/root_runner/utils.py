import os
import signal
import subprocess
import sys

import pamela

from utils.config_files import TEST_PATH, TEST_COMMANDS_FILE

processes = []


def command_runner(cmd, wait_for_output=True):
    if 'test' in sys.argv:
        if cmd.startswith('timeout --foreground'):
            subprocess.run('mkdir -p {}/  > /dev/null 2>&1'.format(TEST_PATH), shell=True, stderr=subprocess.STDOUT,
                           universal_newlines=True)
            subprocess.run('touch {}{}'.format(TEST_PATH, TEST_COMMANDS_FILE), shell=True, stderr=subprocess.STDOUT,
                           universal_newlines=True)
            subprocess.run("echo '{}' >> {}{}".format(cmd, TEST_PATH, TEST_COMMANDS_FILE), shell=True,
                           stderr=subprocess.STDOUT, universal_newlines=True)
            return True, 'done'
    result = ''
    try:
        if wait_for_output:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

        else:
            subprocess.run(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)

        status = True
    except subprocess.CalledProcessError as e:
        if wait_for_output:
            result = str(e.output)
        status = False
    # print("status, result:", status, result)
    return status, result.strip()


def command_runner_popen(cmd, wait_for_output):
    result = ''
    try:
        result = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)
        processes.append(result.pid)
        result = result.communicate()[0].decode('utf-8')
        status = True
    except subprocess.CalledProcessError as e:
        result = str(e.output)
        status = False
    return status, result.strip()


def kill_command_runner():
    try:
        for pid in processes:
            # proc.terminate()
            os.kill(pid, signal.SIGKILL)

        return True
    except Exception as e:
        return False


def file_writer(file, content, mode):
    with open(file, mode) as f:
        f.seek(0)
        f.write(content)
        f.truncate()


def file_reader(file):
    with open(file) as f:
        content = f.read()
    return content


def check_path_exists(path):
    return os.path.exists(path)


def remove_dir(path):
    import shutil

    if check_path_exists(path):
        shutil.rmtree(path)
    return True


def mkdir(path):
    return os.mkdir(path)


def pam_authenticate(username, password):
    username = username
    password = password

    try:
        pamela.authenticate(username, password)
    except pamela.PAMError:
        return False

    return True


def restart_systemd_service(service):
    try:
        result = subprocess.check_output('service {} restart'.format(service), shell=True, stderr=subprocess.STDOUT,
                                         universal_newlines=True)
        status = True
    except subprocess.CalledProcessError as e:
        result = str(e.output)
        status = False

    return status, result.strip()
