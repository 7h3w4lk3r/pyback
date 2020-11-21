from setting import *

# dump clipboard #####################
def clipboard():
    try:
        s = pyperclip.paste()
        pyperclip.copy(s)
        return  "\n\033[1;32;32m[+]\x1b[0m clipboard dumped successfully \033[1;32;32m[+] \n\n\x1b[0m"+s
    except:
        return "\n\033[1;32;31m [-]\x1b[0m dump failed \033[1;32;31m[-] \n\x1b[0m"
