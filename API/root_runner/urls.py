from django.urls import path

from root_runner.views import http_command_runner, http_write_file, http_read_file, http_post_check_path_exists, \
    http_post_mkdir, http_authenticate, http_remove_directory, http_restart_systemd_service
urlpatterns = [
    path('run_command', http_command_runner),
    path('write_file', http_write_file),
    path('read_file', http_read_file),
    path('check_path_exists', http_post_check_path_exists),
    path('mkdir', http_post_mkdir),
    # path('update', http_update),
    path('authenticate', http_authenticate),
    path('remove_dir', http_remove_directory),
    path('restart_systemd_service', http_restart_systemd_service),
]
