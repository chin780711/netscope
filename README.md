# NetScope

NetScope is a Python-based LAN scanning tool that helps discover active devices on a local network and provides basic device and risk information.

## Features
- Scan a subnet or CIDR range
- Discover active devices with ARP scanning
- Show used and unused IP addresses
- Resolve hostnames
- Identify MAC addresses and vendors
- Detect likely device types
- Assign basic risk scores and reasons
- Track device history
- Export results to CSV

## Installation
```bash
git clone https://github.com/chin780711/netscope.git
cd netscope
pip install -r requirements.txt
Usage
python main.py

Example:

192.168.1.0/24
Project Structure
netscope/
├── main.py
├── requirements.txt
├── functions/
├── reports/
├── storage.py
└── README.md
Notes
NetScope is intended for authorized and defensive use only.
ARP scanning works only on the local network segment.
Author

Chin Lun Chen
