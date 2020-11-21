from setting import *

def detectSandboxie():
    try:
        libHandle = ctypes.windll.LoadLibrary("SbieDll.dll")
        return "\n\033[1;32;31m[!]\x1b[0m Sandbox detected \033[1;32;31m[!]\n\x1b[0m"
    except:
        return "\n\033[1;32;32m[+]\x1b[0m doesn't appear to be a sandbox \033[1;32;32m[+]\n\x1b[0m"
