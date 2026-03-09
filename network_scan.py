from ipaddress import ip_network, ip_address
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from rich.table import Table
from rich import print
import socket
import time
import json


# 猜測設備類型
def detect_device_type(hostname, vendor):
    hostname_l = hostname.lower()
    vendor_l = vendor.lower()

    if "router" in hostname_l or "gateway" in hostname_l:
        return "Router"

    if hostname.startswith("BRW") or "brother" in vendor_l:
        return "Printer"

    if "iphone" in hostname_l or "ipad" in hostname_l:
        return "Phone"

    if "android" in hostname_l or "samsung" in vendor_l or "xiaomi" in vendor_l:
        return "Phone / Mobile"

    if "apple" in vendor_l:
        return "Apple Device"

    if "cisco" in vendor_l or "calix" in vendor_l:
        return "Network Device"

    if "intel" in vendor_l or "dell" in vendor_l or "hp" in vendor_l or "lenovo" in vendor_l:
        return "Computer"

    return "-"


# 建立主掃描表格
def build_main_table(devices, full_scan=False):
    table = Table(title="NetScope LAN Scanner")

    table.add_column("#", justify="right")
    table.add_column("IP Address", style="green")

    if full_scan:
        table.add_column("Hostname")

    table.add_column("MAC Address")
    table.add_column("Vendor")
    table.add_column("Device Type")

    if full_scan:
        table.add_column("Open Ports")

    for i, device in enumerate(devices, start=1):
        if full_scan:
            ip, hostname, mac, vendor, device_type, open_ports = device
            table.add_row(
                str(i),
                ip,
                hostname,
                mac,
                vendor,
                device_type,
                open_ports
            )
        else:
            ip, mac, vendor, device_type = device
            table.add_row(
                str(i),
                ip,
                mac,
                vendor,
                device_type
            )

    return table


# 建立新設備表格
def build_new_device_table(new_devices, full_scan=False):
    table = Table(title="⚠ New Devices Detected")

    table.add_column("#", justify="right")
    table.add_column("IP Address", style="green")

    if full_scan:
        table.add_column("Hostname")

    table.add_column("MAC Address")
    table.add_column("Vendor")
    table.add_column("Device Type")

    if full_scan:
        table.add_column("Open Ports")

    for i, device in enumerate(new_devices, start=1):
        if full_scan:
            ip, hostname, mac, vendor, device_type, open_ports = device
            table.add_row(
                str(i),
                ip,
                hostname,
                mac,
                vendor,
                device_type,
                open_ports
            )
        else:
            ip, mac, vendor, device_type = device
            table.add_row(
                str(i),
                ip,
                mac,
                vendor,
                device_type
            )

    return table


# 掃描常見 Port
def scan_ports(ip):
    common_ports = [22, 80, 443, 445, 3389, 9100]
    open_ports = []

    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(str(port))
        s.close()

    return ",".join(open_ports) if open_ports else "-"


# 開始計時
start_time = time.time()

# 掃描模式
scan_mode = input("掃描模式: 1.快速掃描 2.完整掃描 ").strip()
full_scan = scan_mode == "2"

# 使用者輸入網段
cidr = input("輸入網段 (例如 192.168.1.0/24): ").strip()
try:
    network = ip_network(cidr, strict=False)
except ValueError:
    print("[bold red]輸入格式錯誤，請使用像 192.168.1.0/24 或 192.168.1.182/24 這種格式[/bold red]")
    exit()

print("\n[bold cyan]NetScope LAN Scanner[/bold cyan]")
print(f"[dim]Scanning {network}[/dim]\n")

mac_lookup = MacLookup()

# ARP 掃描
packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
result = srp(packet, timeout=2, verbose=0)[0]

devices = []

for sent, received in result:
    ip = received.psrc
    mac = received.hwsrc

    try:
        vendor = mac_lookup.lookup(mac)     # Vendor
    except:
        vendor = "-"

    if full_scan:       
        try:
            hostname = socket.gethostbyaddr(ip)[0]      # Hostname
        except:
            hostname = "-"

        # Open Ports
        open_ports = scan_ports(ip)
        device_type = detect_device_type(hostname, vendor)
        devices.append((ip, hostname, mac, vendor, device_type, open_ports))# 完整掃描固定 6 個值

    else:
        device_type = detect_device_type("-", vendor)
        devices.append((ip, mac, vendor, device_type))  # 快速掃描固定 4 個值


# IP 排序
devices.sort(key=lambda x: ip_address(x[0]))

# 顯示主表格
main_table = build_main_table(devices, full_scan=full_scan)
print(main_table)

# 新設備偵測（以 MAC 為主）
if full_scan:
    current_macs = [device["mac"] for device in devices]   # mac 在第 3 個
else:
    current_macs = [device["ip"] for device in devices]   # mac 在第 2 個

try:
    with open("known_devices.json", "r", encoding="utf-8") as f:
        known_macs = json.load(f)
except:
    known_macs = []

if full_scan:
    new_devices = [device for device in devices if device["mac"] not in known_macs]
else:
    new_devices = [device for device in devices if device["ip"] not in known_macs]

if new_devices:
    print()
    print(build_new_device_table(new_devices, full_scan=full_scan))
else:
    print("\n[bold green]沒有偵測到新設備[/bold green]")

# 更新 known_devices.json
with open("known_devices.json", "w", encoding="utf-8") as f:
    json.dump(current_macs, f, indent=2)

# 統計
total_hosts = len(list(network.hosts()))
used_count = len(devices)
unused_count = total_hosts - used_count

end_time = time.time()
scan_time = round(end_time - start_time, 2)

print("\n[bold yellow]掃描結果[/bold yellow]")
print("正在使用的IP數量:", used_count)
print("未使用的IP數量:", unused_count)
print("掃描耗時:", scan_time, "秒")

# 匯出 CSV
# with open("scan_result.csv", "w", newline="", encoding="utf-8-sig") as file:
#     writer = csv.writer(file)
#     writer.writerow([
#         "No",
#         "IP Address",
#         "Hostname",
#         "MAC Address",
#         "Open Ports"  
#         "Vendor",
#         "Device Type"
#     ])

#     for i, device in enumerate(devices, start=1):
#         writer.writerow([i, *device])

# print("\n[bold cyan]掃描結果已匯出成 scan_result.csv[/bold cyan]")
# print("[bold cyan]已更新 known_devices.json[/bold cyan]")