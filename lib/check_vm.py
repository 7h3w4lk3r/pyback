from lib.setting import *

def detectVM():
    if os_type == "windows":
        try:
            import wmi
            objWMI = wmi.WMI()
            for objDiskDrive in objWMI.query("Select * from Win32_DiskDrive"):
                if "vbox" in objDiskDrive.Caption.lower() or "virtual" in objDiskDrive.Caption.lower():
                    return "\n\033[1;32;31m[!]\x1b[0m Virtual Machine detected \033[1;32;31m[!]\n\x1b[0m"
                return "\n\033[1;32;32m[+]\x1b[0m doesn't appear to be a VM \033[1;32;32m[+]\n\x1b[0m"
        except:
            return "\n\033[1;32;31m[-]\x1b[0m VM check failed, unable to load module wmi  \033[1;32;31m[-]\n\x1b[0m"
    else:
        try:
            checkVM = subprocess.check_output(
                'grep -q ^flags.*\ hypervisor /proc/cpuinfo && echo "This machine is a VM"', shell=True)
            if checkVM == "This machine is a VM":
                return "\n\033[1;32;31m[!]\x1b[0m Virtual Machine detected 033[1;32;31m[!]\n\x1b[0m"
        except subprocess.CalledProcessError:
            return "\n\033[1;32;32m[+]\x1b[0m doesn't appear to be a VM \033[1;32;32m[+]\n\x1b[0m"
        except Exception as e:
            return "\n\033[1;32;31m[-]\x1b[0m VM check failed, unable to grep /proc/cpuinfo " + str(e) + "\033[1;32;31m[-]\n\x1b[0m"
