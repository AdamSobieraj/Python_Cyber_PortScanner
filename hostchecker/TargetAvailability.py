from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP


class TargetAvailability:
    def __init__(self):
        None

    def check_host_availible(self, scan_host, timeout):
        try:
            conf.verb = 0
            pingr = IP(dst=scan_host) / ICMP()
            res = sr1(pingr, timeout=timeout)
            if res is not None:
                return True
        except Exception as inst:
            print(inst)
            return False
