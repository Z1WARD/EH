import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change it's MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    options = parser.parse_args()[0]

    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    elif not options.new_mac:
        parser.error("[-] Please specify a new MAC address, use --help for more info")
    return options


def change_mac(interface, new_mac):
    print("[+] Changing MAC address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    print("[+] 33%")
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    print("[+] 66%")
    subprocess.call(["ifconfig", interface, "up"])
    print("[+] 100% DONE")


def get_current_mac(interface):
    ifconfig_output = subprocess.check_output(["ifconfig", interface])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_output)

    if mac_address_search_result:
        return mac_address_search_result.group()
    else:
        print("[-] Sorry, could not read MAC address.")


options = get_arguments()

current_mac = get_current_mac(options.interface)
print("Current MAC for " + str(options.interface) + " is " + str(current_mac))
change_mac(options.interface, options.new_mac)
current_mac = get_current_mac(options.interface)

if current_mac == options.new_mac:
    print("[+] MAC address was successfully changed to " + str(current_mac))
else:
    print("[-] MAC address did not get changed")
