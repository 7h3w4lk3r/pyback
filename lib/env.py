from lib.setting import *

def get_env():
    env = ''
    for n in os.environ:
        env += "    {0:35}: {1}\n\n".format(n,os.environ.get(n))
    env = env.replace(';','\n{0:39}: '.format(""))
    return env