from config import TRUSTED_DEVICES


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
