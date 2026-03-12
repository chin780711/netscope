from ipaddress import ip_network, ip_address
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from rich import print
import time

from core.storage import (
    load_known_devices,
    save_known_devices,
    load_scan_history,
    save_scan_history,
    build_scan_snapshot,
    compare_with_last_scan,
    load_device_timeline,
    save_device_timeline,
    update_device_timeline,
)
from core.scanner import lookup_vendor, resolve_hostname, scan_ports
from core.device_detection import detect_device_type
from config import TRUSTED_DEVICES
from core.risk_analysis import calculate_risk, get_device_status
from core.reports import (
    build_main_table,
    build_new_device_table,
    show_network_changes,
    export_csv,
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
    timeline_data = load_device_timeline()

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

            risk_score, risk_level, risk_reasons = calculate_risk(
                open_ports, vendor, device_type, is_trusted
            )
            risk_reason = ", ".join(risk_reasons) if risk_reasons else "-"

            status = get_device_status(mac, vendor, device_type, risk_level, is_new)

            mac_key = mac.lower()
            timeline_entry = timeline_data.get(mac_key, {})
            first_seen = timeline_entry.get("first_seen", "-")
            last_seen = timeline_entry.get("last_seen", "-")
            seen_count = timeline_entry.get("seen_count", 0)

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
                    risk_reason,
                    first_seen,
                    last_seen,
                    seen_count,
                )
            )
        else:
            hostname = resolve_hostname(ip)

            device_type = detect_device_type(hostname, vendor, [], mac)

            is_trusted = mac in TRUSTED_DEVICES
            is_new = mac not in known_macs

            risk_score, risk_level, risk_reasons = calculate_risk(
                [], vendor, device_type, is_trusted
            )
            risk_reason = ", ".join(risk_reasons) if risk_reasons else "-"

            status = get_device_status(mac, vendor, device_type, risk_level, is_new)

            mac_key = mac.lower()
            timeline_entry = timeline_data.get(mac_key, {})
            first_seen = timeline_entry.get("first_seen", "-")
            last_seen = timeline_entry.get("last_seen", "-")
            seen_count = timeline_entry.get("seen_count", 0)

            devices.append(
                (
                    ip,
                    hostname,
                    mac,
                    vendor,
                    device_type,
                    status,
                    risk_level,
                    risk_score,
                    risk_reason,
                    first_seen,
                    last_seen,
                    seen_count,
                )
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
    timeline_data = update_device_timeline(devices, full_scan, timeline_data)
    save_device_timeline(timeline_data)

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
    export_choice = input("\n是否匯出 CSV？(y/n): ").strip().lower()
    if export_choice == "y":
        export_csv(devices, full_scan=full_scan)


if __name__ == "__main__":
    main()
