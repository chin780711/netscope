from ipaddress import ip_network, ip_address
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from rich.table import Table
from rich import print
import socket
import time
import json
import os
import csv


KNOWN_DEVICES_FILE = "known_devices.json"
SCAN_HISTORY_FILE = "scan_history.json"
COMMON_PORTS = [22, 80, 443, 445, 3389, 9100]

TRUSTED_DEVICES = {
    # "AA:BB:CC:DD:EE:FF": "My Laptop",
    # "11:22:33:44:55:66": "Home Router",
}


# 猜測設備類型
def detect_device_type(hostname="", vendor="", open_ports=None, mac=""):
    hostname_l = (hostname or "").lower()
    vendor_l = (vendor or "").lower()
    open_ports = open_ports or []
    mac = (mac or "").lower()

    # --- Hostname 判斷 ---
    if "router" in hostname_l or "gateway" in hostname_l:
        return "Router"

    if hostname.upper().startswith("BRW"):
        return "Printer"

    if "iphone" in hostname_l:
        return "iPhone"

    if "ipad" in hostname_l:
        return "iPad"

    if "android" in hostname_l:
        return "Android Device"

    if "macbook" in hostname_l or "imac" in hostname_l or "mac mini" in hostname_l:
        return "Apple Computer"

    if "docker" in hostname_l:
        return "Possible Container Host"

    if "wsl" in hostname_l:
        return "Possible WSL Environment"

    if "vm" in hostname_l or "virtual" in hostname_l:
        return "Possible Virtual Machine"

    # --- Vendor 判斷 ---
    if "brother" in vendor_l or "epson" in vendor_l or "canon" in vendor_l:
        return "Printer"

    if "hp" in vendor_l:
        if 9100 in open_ports or 515 in open_ports or 631 in open_ports:
            return "Printer"
        return "Computer"

    if "apple" in vendor_l:
        if "iphone" in hostname_l:
            return "iPhone"
        if "ipad" in hostname_l:
            return "iPad"
        return "Apple Device"

    if (
        "samsung" in vendor_l
        or "xiaomi" in vendor_l
        or "huawei" in vendor_l
        or "google" in vendor_l
    ):
        return "Phone / Mobile"

    if (
        "cisco" in vendor_l
        or "calix" in vendor_l
        or "tp-link" in vendor_l
        or "ubiquiti" in vendor_l
        or "netgear" in vendor_l
        or "mikrotik" in vendor_l
    ):
        return "Network Device"

    if "vmware" in vendor_l:
        return "Possible VMware VM"

    if "oracle" in vendor_l or "pcs systemtechnik" in vendor_l:
        return "Possible VirtualBox VM"

    if (
        "intel" in vendor_l
        or "dell" in vendor_l
        or "lenovo" in vendor_l
        or "asus" in vendor_l
        or "acer" in vendor_l
        or "msi" in vendor_l
    ):
        return "Computer"

    # --- Port 判斷 ---
    if 9100 in open_ports or 515 in open_ports or 631 in open_ports:
        return "Printer"

    if 3389 in open_ports:
        return "Computer (RDP Enabled)"

    if 22 in open_ports and 80 in open_ports and 443 in open_ports:
        return "Possible Server / Network Appliance"

    if 80 in open_ports or 443 in open_ports:
        return "Web Device / Server"

    # --- MAC 特徵判斷 ---
    if is_locally_administered_mac(mac):
        return "Randomized / Private MAC Device"

    # --- 最後推測 ---
    return "Unknown"


# 本地MAC位置
def is_locally_administered_mac(mac):
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0b00000010)
    except (ValueError, IndexError):
        return False


# 風險評分與可疑設備判斷
def calculate_risk(open_ports, vendor, device_type, is_trusted):
    score = 0
    reasons = []

    vendor_l = (vendor or "").lower()

    if not is_trusted:
        score += 2
        reasons.append("Unknown MAC")

    if 445 in open_ports:
        score += 3
        reasons.append("SMB exposed")

    if 3389 in open_ports:
        score += 3
        reasons.append("RDP exposed")

    if 22 in open_ports:
        score += 1
        reasons.append("SSH exposed")

    if 80 in open_ports or 443 in open_ports:
        score += 1
        reasons.append("Web service")

    if 9100 in open_ports:
        score += 1
        reasons.append("Printer port")

    if vendor == "-" or vendor.strip() == "":
        score += 1
        reasons.append("Unknown vendor")

    if device_type in ["-", "Unknown"]:
        score += 1
        reasons.append("Unknown device type")

    if any(keyword in vendor_l for keyword in ["esp", "iot", "tuya"]):
        score += 2
        reasons.append("Possible IoT device")

    if score >= 6:
        level = "High"
    elif score >= 3:
        level = "Medium"
    else:
        level = "Low"

    return score, level, reasons


def get_device_status(mac, vendor, device_type, risk_level, is_new):
    if mac in TRUSTED_DEVICES:
        return "Trusted"

    if risk_level == "High":
        return "Suspicious"

    if is_new and (vendor == "-" or device_type in ["-", "Unknown"]):
        return "Suspicious"

    if is_new:
        return "New"

    return "Known"


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
    table.add_column("Status")
    table.add_column("Risk")
    table.add_column("Score", justify="right")

    if full_scan:
        table.add_column("Open Ports")

    for i, device in enumerate(devices, start=1):
        if full_scan:
            (
                ip,
                hostname,
                mac,
                vendor,
                device_type,
                open_ports,
                status,
                risk_level,
                risk_score,
            ) = device
            table.add_row(
                str(i),
                ip,
                hostname,
                mac,
                vendor,
                device_type,
                status,
                risk_level,
                str(risk_score),
                open_ports,
            )
        else:
            ip, mac, vendor, device_type, status, risk_level, risk_score = device
            table.add_row(
                str(i),
                ip,
                mac,
                vendor,
                device_type,
                status,
                risk_level,
                str(risk_score),
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
    table.add_column("Status")
    table.add_column("Risk")
    table.add_column("Score", justify="right")

    if full_scan:
        table.add_column("Open Ports")

    for i, device in enumerate(new_devices, start=1):
        if full_scan:
            (
                ip,
                hostname,
                mac,
                vendor,
                device_type,
                open_ports,
                status,
                risk_level,
                risk_score,
            ) = device
            table.add_row(
                str(i),
                ip,
                hostname,
                mac,
                vendor,
                device_type,
                status,
                risk_level,
                str(risk_score),
                open_ports,
            )
        else:
            ip, mac, vendor, device_type, status, risk_level, risk_score = device
            table.add_row(
                str(i),
                ip,
                mac,
                vendor,
                device_type,
                status,
                risk_level,
                str(risk_score),
            )

    return table


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


# 讀取 known devices
def load_known_devices():
    if not os.path.exists(KNOWN_DEVICES_FILE):
        return {"known_macs": []}

    try:
        with open(KNOWN_DEVICES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

            # 舊版相容：如果讀到的是 list，就轉成新版格式
            if isinstance(data, list):
                return {"known_macs": data}

            if isinstance(data, dict) and "known_macs" in data:
                return data

    except (json.JSONDecodeError, OSError):
        pass

    return {"known_macs": []}


# 儲存 known devices
def save_known_devices(mac_list):
    data = {
        "known_macs": mac_list,
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    try:
        with open(KNOWN_DEVICES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except OSError as e:
        print(f"[bold red]儲存 {KNOWN_DEVICES_FILE} 失敗: {e}[/bold red]")


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


# 匯出 CSV
def export_csv(devices, full_scan=False, filename="scan_result.csv"):
    try:
        with open(filename, "w", newline="", encoding="utf-8-sig") as file:
            writer = csv.writer(file)

            if full_scan:
                writer.writerow(
                    [
                        "No",
                        "IP Address",
                        "Hostname",
                        "MAC Address",
                        "Vendor",
                        "Device Type",
                        "Status",
                        "Risk",
                        "Score",
                        "Open Ports",
                    ]
                )

                for i, device in enumerate(devices, start=1):
                    (
                        ip,
                        hostname,
                        mac,
                        vendor,
                        device_type,
                        open_ports,
                        status,
                        risk_level,
                        risk_score,
                    ) = device
                    writer.writerow(
                        [
                            i,
                            ip,
                            hostname,
                            mac,
                            vendor,
                            device_type,
                            status,
                            risk_level,
                            risk_score,
                            open_ports,
                        ]
                    )

            else:
                writer.writerow(
                    [
                        "No",
                        "IP Address",
                        "MAC Address",
                        "Vendor",
                        "Device Type",
                        "Status",
                        "Risk",
                        "Score",
                    ]
                )

                for i, device in enumerate(devices, start=1):
                    ip, mac, vendor, device_type, status, risk_level, risk_score = (
                        device
                    )
                    writer.writerow(
                        [
                            i,
                            ip,
                            mac,
                            vendor,
                            device_type,
                            status,
                            risk_level,
                            risk_score,
                        ]
                    )

        print(f"\n[bold cyan]掃描結果已匯出成 {filename}[/bold cyan]")
    except OSError as e:
        print(f"[bold red]CSV 匯出失敗: {e}[/bold red]")


# 讀取最後掃描內容
def load_scan_history():
    try:
        with open(SCAN_HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    return []


# 儲存掃描內容
def save_scan_history(history):
    with open(SCAN_HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


# 建立掃描檔案
def build_scan_snapshot(devices, full_scan=False):
    snapshot = []

    for device in devices:
        if full_scan:
            (
                ip,
                hostname,
                mac,
                vendor,
                device_type,
                open_ports,
                status,
                risk_level,
                risk_score,
            ) = device
            snapshot.append(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "mac": mac,
                    "vendor": vendor,
                    "device_type": device_type,
                    "open_ports": open_ports,
                    "status": status,
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                }
            )
        else:
            ip, mac, vendor, device_type, status, risk_level, risk_score = device
            snapshot.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "device_type": device_type,
                    "status": status,
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                }
            )

    return snapshot


# 比對最後掃描結果
def compare_with_last_scan(history, current_snapshot):
    if not history:
        return [], []

    last_snapshot = history[-1]["devices"]

    old_macs = {device["mac"] for device in last_snapshot}
    new_macs = {device["mac"] for device in current_snapshot}

    added = [d for d in current_snapshot if d["mac"] not in old_macs]
    removed = [d for d in last_snapshot if d["mac"] not in new_macs]

    return added, removed


# 顯示目前網路
def show_network_changes(added, removed):
    if not added and not removed:
        print("\n[bold green]Network change tracking: 無變化[/bold green]")
        return

    if added:
        print("\n[bold cyan]Network change tracking - 新增設備[/bold cyan]")
        for d in added:
            print(
                f"[+] {d['mac']}  {d.get('ip', '-')}  "
                f"{d.get('vendor', '-')}  {d.get('device_type', '-')}"
            )

    if removed:
        print("\n[bold magenta]Network change tracking - 消失設備[/bold magenta]")
        for d in removed:
            print(
                f"[-] {d['mac']}  {d.get('ip', '-')}  "
                f"{d.get('vendor', '-')}  {d.get('device_type', '-')}"
            )


def main():
    start_time = time.time()

    scan_mode = input("掃描模式: 1.快速掃描 2.完整掃描 ").strip()
    full_scan = scan_mode == "2"

    cidr = input("輸入網段 (例如 192.168.1.0/24): ").strip()
    try:
        network = ip_network(cidr, strict=False)
    except ValueError:
        print(
            "[bold red]輸入格式錯誤，請使用像 192.168.1.0/24 或 192.168.1.182/24 這種格式[/bold red]"
        )
        return

    print("\n[bold cyan]NetScope LAN Scanner[/bold cyan]")
    print(f"[dim]Scanning {network}[/dim]\n")

    mac_lookup = MacLookup()

    # ARP 掃描
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))

    try:
        result = srp(packet, timeout=2, verbose=0)[0]
    except Exception as e:
        print(f"[bold red]ARP 掃描失敗: {e}[/bold red]")
        return

    known_data = load_known_devices()
    known_macs = known_data.get("known_macs", [])

    devices = []

    for _, received in result:
        ip = received.psrc
        mac = received.hwsrc
        vendor = lookup_vendor(mac_lookup, mac)

        if full_scan:
            hostname = resolve_hostname(ip)

            open_ports = scan_ports(ip)
            device_type = detect_device_type(hostname, vendor, open_ports, mac)

            is_trusted = mac in TRUSTED_DEVICES
            is_new = mac not in known_macs

            risk_score, risk_level, _ = calculate_risk(
                open_ports, vendor, device_type, is_trusted
            )
            status = get_device_status(mac, vendor, device_type, risk_level, is_new)

            devices.append(
                (
                    ip,
                    hostname,
                    mac,
                    vendor,
                    device_type,
                    ",".join(map(str, open_ports)) if open_ports else "-",
                    status,
                    risk_level,
                    risk_score,
                )
            )
        else:
            device_type = detect_device_type("-", vendor, [], mac)

            is_trusted = mac in TRUSTED_DEVICES
            is_new = mac not in known_macs

            risk_score, risk_level, _ = calculate_risk(
                [], vendor, device_type, is_trusted
            )
            status = get_device_status(mac, vendor, device_type, risk_level, is_new)

            devices.append(
                (ip, mac, vendor, device_type, status, risk_level, risk_score)
            )

    # IP 排序
    devices.sort(key=lambda x: ip_address(x[0]))

    # 顯示主表格
    main_table = build_main_table(devices, full_scan=full_scan)
    print(main_table)

    # 新設備偵測（以 MAC 為主）
    if full_scan:
        current_macs = [device[2] for device in devices]
    else:
        current_macs = [device[1] for device in devices]

    if full_scan:
        new_devices = [device for device in devices if device[2] not in known_macs]
    else:
        new_devices = [device for device in devices if device[1] not in known_macs]

    if new_devices:
        print()
        print(build_new_device_table(new_devices, full_scan=full_scan))
    else:
        print("\n[bold green]沒有偵測到新設備[/bold green]")

    # 更新 known_devices.json
    save_known_devices(current_macs)

    history = load_scan_history()
    current_snapshot = build_scan_snapshot(devices, full_scan=full_scan)
    added, removed = compare_with_last_scan(history, current_snapshot)
    show_network_changes(added, removed)

    history.append(
        {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "device_count": len(current_snapshot),
            "devices": current_snapshot,
        }
    )

    history = history[-20:]  # 只保留最近 20 次
    save_scan_history(history)

    # 統計
    total_hosts = len(list(network.hosts()))
    used_count = len(devices)
    unused_count = max(total_hosts - used_count, 0)

    end_time = time.time()
    scan_time = round(end_time - start_time, 2)

    print("\n[bold yellow]掃描結果[/bold yellow]")
    print("正在使用的IP數量:", used_count)
    print("未使用的IP數量(依 ARP 回應推估):", unused_count)
    print("掃描耗時:", scan_time, "秒")

    if full_scan:
        high_risk_count = sum(1 for d in devices if d[7] == "High")
        medium_risk_count = sum(1 for d in devices if d[7] == "Medium")
    else:
        high_risk_count = sum(1 for d in devices if d[5] == "High")
        medium_risk_count = sum(1 for d in devices if d[5] == "Medium")

    print("高風險設備數量:", high_risk_count)
    print("中風險設備數量:", medium_risk_count)

    # 是否匯出 CSV
    # export_choice = input("\n是否匯出 CSV？(y/n): ").strip().lower()
    # if export_choice == "y":
    #     export_csv(devices, full_scan=full_scan)


if __name__ == "__main__":
    main()
