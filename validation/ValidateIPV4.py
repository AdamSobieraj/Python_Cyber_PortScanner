import ipaddress


def validate_ipv4(target_host_ip):
    try:
        ipaddress.ip_address(target_host_ip)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    validate_ipv4("10.10.10.1")
