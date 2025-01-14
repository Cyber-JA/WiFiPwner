import os
import sys
import argparse
import textwrap
import subprocess
import re

# Handle user CTRL+C
def signal_handler(sig, frame):
    print("[-] CTRL+C detected.")

def manage_interface(interface):
    command = "iwconfig " + interface
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        if "Monitor" in result:
            print("[*] Interface already in monitor mode...proceeding")
        else:
            print("[*] Setting interface in monitor mode...wait...")
            try:
                monitor_mode_command = "airmon-ng start " + interface
                active_monitor = subprocess.check_output(monitor_mode_command, shell=True, text=True)
            except subprocess.CalledProcessError as e:
                print("Error: " + e)
    except subprocess.CalledProcessError as e:
        print("No such device: " + interface)
        return

def check_MAC_format(mac_addr):
    mac_regex = r"^([0-9A-Fa-f]{2}([-:]))([0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2}$"
    return bool(re.match(mac_regex, mac_addr))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Auto deauthenticator tool using aircrack-ng suite',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example:
    wifipwner.py -b 0A:1B:2C:3D:4E:5F -t 0A:1B:2C:3D:4E:5F -c 10 -a bruter -i wlan1mon
    ''')
    )
    parser.add_argument('-t', '--target', help='MAC of the target to deauthenticate (0 to broadcast)')
    parser.add_argument('-b', '--bssid', help='MAC address of the AP')
    parser.add_argument('-c', '--counter', help='Number of deauth requests to be sent', type=int)
    parser.add_argument('-i', '--interface', help='Network interface to be used')
    parser.add_argument('-a', '--attack', help='Attack mode to be used (bruter, dictionary)', type=str)
    args = parser.parse_args()

    try:
        if args.target == None or check_MAC_format(args.target) == False:
            print("[!] Missing or wrong Target format...Aborting")
        elif args.bssid == None or check_MAC_format(args.bssid) == False:
            print("[!] Missing or wrong BSSID format...Aborting")
        elif args.counter == None:
            print("[!] Missing Counter...Aborting")
        elif args.interface == None:
            print("[!] Missing Interface...Aborting")
        elif args.attack == None:
            print("[!] Missing Attack mode...Aborting")
        else:
            target = args.target
            bssid = args.bssid
            counter = args.counter
            interface = args.interface
            attack = args.attack
            manage_interface(interface=interface)
    except KeyboardInterrupt:


