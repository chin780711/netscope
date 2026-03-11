from rich.table import Table
from rich import print


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
