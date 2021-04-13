from lib.setting import *

# change working directory ########################
def chdir(path):
    try:
        os.chdir(path)
        return "\n\033[32m[+]\x1b[0m dir changed to " + os.getcwd() + " \033[32m[+]\n\x1b[0m"
    except Exception as e:
        return "\n\033[31m[-]\x1b[0m no such file or directory \033[31m[-]\n\x1b[0m"