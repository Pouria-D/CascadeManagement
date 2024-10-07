import os

from django.http import HttpResponse

from root_runner.utils import command_runner, file_writer, file_reader, check_path_exists, pam_authenticate, remove_dir, restart_systemd_service


def http_command_runner(request):
    cmd = request.POST['cmd']
    wait_for_output = request.POST['wait_for_output']
    status, result = command_runner(cmd, wait_for_output)
    if not status:
        return HttpResponse(status=400, content=result)

    return HttpResponse(result)


def http_write_file(request):
    file = request.POST['file']
    content = request.POST['content']
    mode = request.POST['mode']
    file_writer(file, content, mode)
    return HttpResponse()


def http_read_file(request):
    file = request.POST['file']
    result = file_reader(file)
    return HttpResponse(result)


def http_post_check_path_exists(request):
    path = request.POST['path']
    status = check_path_exists(path)
    return HttpResponse(status)


def http_remove_directory(request):
    path = request.POST['path']
    status = remove_dir(path)
    return HttpResponse(status)


def http_post_mkdir(request):
    path = request.POST['path']
    os.makedirs(path, 0o744)
    return HttpResponse()


# def http_update(request):
#     path = request.POST['path']
#     s, o = install_update(path)
#     if not s:
#         return HttpResponse(o, status=400)
#     else:
#         return HttpResponse('ok')


def http_authenticate(request):
    username = request.POST['username']
    password = request.POST['password']

    is_authenticated = pam_authenticate(username, password)

    if not is_authenticated:
        return HttpResponse(False, status=400)
    else:
        return HttpResponse('ok')


def http_restart_systemd_service(request):
    service = request.POST['service']
    status, result = restart_systemd_service(service)
    if not status:
        return HttpResponse(status=400, content=result)

    return HttpResponse(result)

