import json
import time
import os
from config import KNOWN_DEVICES_FILE
from config import SCAN_HISTORY_FILE


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
