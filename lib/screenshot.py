from setting import *
# take screenshot ###################
def screenshot():
    try:
        with mss() as screenshot:
            screenshot.shot()
    except:
        pass