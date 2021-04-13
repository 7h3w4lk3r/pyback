from lib.setting import *

def rdp(switch):
    if os_type == "windows":
        try:
            import _winreg
            DEVNULL = open(os.devnull, 'wb')
            # check if rdp is enabled
            rdp_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Control\\Terminal Server')
            val=_winreg.QueryValueEx(rdp_key, "fDenyTSConnections")
            if val[0] == 0:
                rdp_stat =  True # RDP is enabled
            else:
                rdp_stat = False # RDP is  disabled

            # check the switch command (on/off)
            if switch == "on":
                if rdp_stat:
                    return "\n\033[1;32;33m[!]\x1b[0m RDP is already turned on \033[1;32;33m[!]\x1b[0m\n"
                else:
                    try:
                        cmd = 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'
                        subprocess.check_output(cmd, shell=True, stderr=DEVNULL, stdin=DEVNULL)
                        return "\n\033[1;32;32m[+]\x1b[0m RDP turned on \033[1;32;32m[+]\x1b[0m\n"
                    except:
                        pass

            if switch == "off":
                if not rdp_stat:
                    return "\n\033[1;32;33m[!]\x1b[0m RDP is already turned off \033[1;32;33m[!]\x1b[0m\n"
                else:
                    try:
                        cmd = 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f'
                        subprocess.check_output(cmd, shell=True, stderr=DEVNULL, stdin=DEVNULL)
                        return "\n\033[1;32;32m[+]\x1b[0m RDP turned off \033[1;32;32m[+]\x1b[0m\n"
                    except:
                        pass
        except:
            return "\033[1;32;31m[-]\x1b[0m Error occurred while switching RDP \033[1;32;31m[-]\x1b[0m"
    else:
        return "\n\033[1;32;33m[!]\x1b[0m target is not a windows machine \033[1;32;33m[!]\n\x1b[0m"







