#!/usr/bin/python
# -*- encoding: utf-8 -*-

import subprocess
import platform

# detect OS type ###############
if "Linux" in platform.uname():
    os_type = "linux"
else:
    os_type = "windows"


# color codes ###########
red = "\033[1;32;31m"
green = "\033[1;32;32m"
yellow = "\033[1;32;33m"
blue = "\033[1;32;34m"
cyan = "\033[1;32;36m"
black = "\033[1;32;30m"
r = "\x1b[0m"

banner = yellow + """

                        ██████╗░██╗░░░██╗██████╗░░█████╗░░█████╗░██╗░░██╗
                        ██╔══██╗╚██╗░██╔╝██╔══██╗██╔══██╗██╔══██╗██║░██╔╝
                        ██████╔╝░╚████╔╝░██████╦╝███████║██║░░╚═╝█████═╝░
                        ██╔═══╝░░░╚██╔╝░░██╔══██╗██╔══██║██║░░██╗██╔═██╗░
                        ██║░░░░░░░░██║░░░██████╦╝██║░░██║╚█████╔╝██║░╚██╗
                        ╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝


                                    Installation Script 
                                    ===================

                                    Created by: 7h3w4lk3r

                                 https://github.com/7h3w4lk3r
                                 Email : bl4ckr4z3r@gmail.com\n\n
""" + r

error_banner = red,"""
\n\n
          [-] installation failed [-]

please make sure:

1. python 2 is installed correctly
2. you have a working network connection for pip
3. there are no mismatches in python packages

""",r

try:
    if os_type == "linux":
        subprocess.call("clear",shell=True)
        print banner
        print green, "\n[+] Local system type: LINUX [+]\n",r
        print yellow, "\n[*] Installing requirements using pip [*]\n\n",r
        subprocess.call("pip install -r requirements/linux_requirements.txt", shell=True)
    else:
        subprocess.call("cls",shell=True)
        print banner
        print green, "\n[+] Local system type: WINDOWS [+]\n\n",r
        print yellow, "[*] Installing requirements using pip [*]\n\n",r
        subprocess.call("pip install -r requirements\\windows_requirements.txt", shell=True)
    print green,"""\n\n
                            [+] Installation completed successfully [+] 
                       run config.py to generate new settings or run the CNC\n\n""",r
except KeyboardInterrupt:
    exit(0)
except:
    print error_banner

