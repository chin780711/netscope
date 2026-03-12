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
