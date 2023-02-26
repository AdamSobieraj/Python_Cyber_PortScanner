from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP

# Config
TIMEOUT = 0.5
TCP_SYN_FLAG = 'S'

target = input("Please add target: ")
registered_Ports = range(1,1023)
open_ports = []

def scanport(port):
    source_port = RandShort()
    conf.verb = 0
    dst_port = 22

    # pkt = IP(dst=target) / TCP(sport=source_port, dport=dst_port, flags=TCP_SYN_FLAG)
    # response = sr1(pkt, timeout=TIMEOUT)

    pingr = IP(dst="192.168.200.254") / ICMP()
    response = sr1(pingr)

    print(response)

    if response is None:
        return False

scanport(22)

