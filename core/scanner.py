import socket
from config import COMMON_PORTS


# 掃描常見 Port
def scan_ports(ip):
    open_ports = []

    for port in COMMON_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except OSError:
            continue
    return open_ports


# 取得 hostname
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "-"


# 取得 vendor
def lookup_vendor(mac_lookup, mac):
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return "-"
