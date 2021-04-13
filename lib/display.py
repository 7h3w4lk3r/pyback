from lib.setting import *


def display(switch):
    try:
        if switch == "on":
            if os_type == "windows":
                WM_SYSCOMMAND = 274
                HWND_BROADCAST = 65535
                SC_MONITORPOWER = 61808
                ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)
                return "\n\033[1;32;32m[+]\x1b[0m display turned on \033[1;32;32m[+]\x1b[0m\n"
            if os_type == "linux":
                subprocess.check_output('xset dpms force on' + "; exit 0", shell=True, stderr=subprocess.STDOUT)
                return "\n\033[1;32;32m[+]\x1b[0m display turned on \033[1;32;32m[+]\x1b[0m\n"

        if switch == "off":
            if os_type == "windows":
                WM_SYSCOMMAND = 274
                HWND_BROADCAST = 65535
                SC_MONITORPOWER = 61808
                ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)
                return "\n\033[1;32;32m[+]\x1b[0m display turned off \033[1;32;32m[+]\x1b[0m\n"
            if os_type == "linux":
                subprocess.check_output('xset dpms force off' + "; exit 0", shell=True, stderr=subprocess.STDOUT)
                return "\n\033[1;32;32m[+]\x1b[0m display turned off \033[1;32;32m[+]\x1b[0m\n"

    except:
        return "\033[1;32;31m[-]\x1b[0m Error occurred while switching UAC \033[1;32;31m[-]\x1b[0m"