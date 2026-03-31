
## Tech Stack

- Python
- Scapy
- ipaddress
- socket
- subprocess
- csv
- json
- time
- mac-vendor-lookup
- rich

## Installation

Clone the repository:

```bash
git clone https://github.com/chin780711/netscope.git
cd netscope

Install dependencies:

pip install -r requirements.txt
Usage

Run the program:

python main.py

Then enter the subnet or CIDR range you want to scan, for example:

192.168.1.0/24
Output

NetScope provides results directly in the terminal and can export scan results for later analysis.

Terminal Output
Clean table view using rich
Easy-to-read device list
Highlighted active devices
Export
CSV report for scan results
JSON/device history support depending on implementation
Risk Scoring

NetScope includes a simple risk scoring mechanism to provide basic security awareness.

Examples of factors that may increase risk include:

Unknown vendor
Unknown hostname
Suspicious or uncommon device behavior
Potential exposure indicators

The risk system is intended as a lightweight visibility aid, not as a full vulnerability scanner.

Device Tracking

NetScope keeps track of device history to help users understand network changes over time.

Tracked fields include:

First seen
Last seen
Seen count

This helps identify:

Newly appeared devices
Devices that disappear and reappear
Frequently seen hosts
Possible changes in the local network environment
Network Change Detection

By comparing scan history, NetScope can help identify:

New devices added to the network
Devices no longer present
Changes in known device visibility over time

This is useful for basic network awareness and anomaly observation.

Use Cases
Home network visibility
Small office network discovery
Cybersecurity learning projects
Basic device inventory
Detecting unknown devices on a LAN
Practicing Python and network security concepts
Limitations
ARP scanning works only on the local network segment
Hostname resolution may not always succeed
Vendor detection depends on MAC vendor lookup availability
Device type detection is heuristic-based and may not always be accurate
Risk scoring is simplified and should not be treated as a full security assessment
Future Improvements

Possible future enhancements include:

Quick scan vs full scan modes
Better hostname detection
Optional port scanning
Improved device type classification
Stronger risk logic and rule customization
Web dashboard or GUI version
Historical report comparison
Alerting for new or suspicious devices
Project Structure

Example structure:

netscope/
├── main.py
├── requirements.txt
├── functions/
├── reports/
├── storage.py
└── README.md

The actual structure may vary depending on the current version of the project.

Ethical Use

NetScope is intended for authorized and defensive use only.
Use this tool only on networks you own or have explicit permission to assess.

Author

Chin Lun Chen

GitHub: https://github.com/chin780711/netscope

License

This project is for educational and personal portfolio purposes.
You may add an official license later if needed.
