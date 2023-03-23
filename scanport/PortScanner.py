from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP


class PortScanner:

    def __init__(self, target, timeout_half_sec, timeout_two_sec, TCP_RST_FLAG, TCP_SYN_FLAG):
        self.timeout_two_sec = timeout_two_sec
        self.TCP_SYN_FLAG = TCP_SYN_FLAG
        self.target = target
        self.timeout_half_sec = timeout_half_sec
        self.TCP_RST_FLAG = TCP_RST_FLAG

    def scan_potrs(self, dst_port):
        source_port = RandShort()
        conf.verb = 0

        pkt = IP(dst=self.target) / TCP(sport=source_port, dport=dst_port, flags=self.TCP_SYN_FLAG)
        syn_pkt = sr1(pkt, timeout=self.timeout_half_sec)

        if syn_pkt is None:
            return False
        elif not syn_pkt.haslayer(TCP):
            return False
        elif syn_pkt.haslayer(TCP):
            var = syn_pkt[TCP].flags & 0x12 == 0x12
            pkt = IP(dst=self.target) / TCP(sport=source_port, dport=dst_port, flags=self.TCP_RST_FLAG)
            sr(pkt, timeout=self.timeout_two_sec)
            return var
