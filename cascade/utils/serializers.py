from rest_framework import serializers

import platform    # For getting the operating system name
import subprocess  # For executing a shell command


class SingleIPSerializer(serializers.Serializer):
    ip = serializers.IPAddressField(required=True)

def ping(address):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower()=='windows' else '-c'
    
    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '3', address]
    res = subprocess.call(command)
    
    
    if res == 0:
        return "enabled"
    elif res == 2:
        return "disabled"
    else:
        return "failed"
    
        
    


