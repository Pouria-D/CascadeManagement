import subprocess
from time import sleep

FILE = "/tmp/default_route_seen.txt"

while True:
    sleep(5)
    cmd = 'ip route show table main | grep default'
    ps = subprocess.Popen(cmd, shell=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    default_route = ps.communicate()[0]
    if ps.returncode != 0:
        continue
    default_route = default_route.strip()
    if default_route:

        cmd = 'touch ' + FILE
        ps = subprocess.Popen(cmd, shell=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        create_file = ps.communicate()[0]

        cmd = 'echo "$(date)" >> ' + FILE
        ps = subprocess.Popen(cmd, shell=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        write_to_file = ps.communicate()[0]

        routes = default_route.split('\n')
        for route in routes:
            cmd = 'ip route del default table main'
            ps = subprocess.Popen(cmd, shell=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            del_route = ps.communicate()[0]

            cmd = 'ip route add table default ' + route
            ps = subprocess.Popen(cmd, shell=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            add_route = ps.communicate()[0]
