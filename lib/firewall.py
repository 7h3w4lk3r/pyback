from setting import *

# set firewall rules ###############################################################################
def firewall(direction, port, name):
    if os_type == "windows":
        rule = 'netsh advfirewall firewall add rule name=' + str(name) + ' protocol=TCP dir=' + str(
            direction) + ' localport= ' + str(port) + ' action=allow'
    else:
        if direction == "in":
            direction = "INPUT"
        if direction == "out":
            direction = "OUTPUT"
        rule = 'iptables -A ' + str(direction) + ' -p tcp --dport ' + str(port) + ' -j ACCEPT'
    try:
        subprocess.call(rule, shell=True)
        return "\n\033[1;32;32m[+]\x1b[0m firewall rule added successfully \033[1;32;32m[+]\n\x1b[0m"
    except:
        return "\n\033[1;32;31m[-]\x1b[0m failed to add firewall rule \033[1;32;31m[-]\n\x1b[0m"
        pass