# Suspicious File Transfer Detector

A Linux-based cybersecurity tool that analyzes network traffic and detects potentially suspicious file transfer behavior using statistical anomaly detection.

The tool captures or processes PCAP traffic data, builds a baseline of normal transfer behavior, and flags activity that exceeds expected size or frequency thresholds.

---

## Features

* Analyze PCAP network traffic files
* Extract transfer-related network data automatically using tshark
* Detect unusually large transfers
* Detect abnormal transfer frequency
* Group suspicious activity into time windows
* Generate SOC-style suspicious activity reports
* Configurable detection thresholds
* Safe handling of incomplete or malformed data

---

## Technologies Used

* Python 3
* Linux
* tshark
* tcpdump
* grep
* awk

---

## Project Structure

```text
suspicious-transfer-detector/
│
├── main.py
├── captures/
├── output/
├── config/
│   └── config.json
│
├── src/
│   ├── __init__.py
│   ├── ingest.py
│   ├── parser.py
│   ├── baseline.py
│   ├── detector.py
│   └── utils.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Installation

Update packages and install required tools:

```bash
sudo apt update

sudo apt install tshark tcpdump python3 python3-pip
```

Verify installation:

```bash
tshark --version
tcpdump --version
python3 --version
```

---

## Capturing Network Traffic

Start packet capture:

```bash
sudo tcpdump -i any -w captures/traffic.pcap
```

Stop capture with:

```text
CTRL + C
```

---

## Generating Suspicious Traffic (Testing)

### Large Transfer Simulation

```bash
wget http://speedtest.tele2.net/10MB.zip
```

### High Frequency Request Simulation

```bash
for i in {1..50}; do curl -s https://example.com > /dev/null; done
```

### Repeated Connection Simulation

```bash
for i in {1..30}; do ping -c 1 8.8.8.8; done
```

These commands help generate suspicious patterns for testing anomaly detection.

---

## Running the Detector

Analyze a PCAP file:

```bash
python3 main.py --pcap captures/traffic.pcap
```

---

## Example Output

```text
======================================
  Suspicious File Transfer Detector
  Network Security Analysis Tool
======================================

[1/4] Extracting network data from PCAP...
[+] CSV generated at: output/transfers.csv

[2/4] Parsing network events...
[+] Parsed events: 1240

[3/4] Building baseline model...
[+] Baseline computed:
{
  'avg_size': 842.3,
  'max_size_threshold': 5000.1,
  'avg_frequency': 12.4,
  'max_frequency_threshold': 25.7
}

[4/4] Running anomaly detection...

=== SUSPICIOUS ACTIVITY REPORT ===

Source IP: 192.168.1.10
Destination IP: 8.8.8.8
Window: 10234

Reasons:
 - High transfer volume detected
 - Abnormal transfer frequency

--------------------------------------

[✓] Analysis complete.
```

---

## Configuration

The detector uses:

```text
config/config.json
```

Example configuration:

```json
{
  "window_size": 60,
  "size_threshold_bytes": 5000000,
  "frequency_threshold": 20,
  "enable_dynamic_baseline": true,
  "max_alerts": 100,
  "ignored_protocols": [
    "ARP",
    "ICMP"
  ]
}
```

---

## Detection Logic

The system detects suspicious behavior using:

* transfer size anomalies
* abnormal transfer frequency
* burst transfer activity
* statistical baseline deviation

Traffic is grouped into configurable time windows for analysis.

---

## Keywords

Cybersecurity, Network Monitoring, Anomaly Detection

