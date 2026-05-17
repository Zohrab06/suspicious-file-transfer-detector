
import subprocess
import os
import sys


def run_tshark(pcap_path: str, output_csv: str):
    
    # Automatically extracts network data from PCAP using tshark.

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    command = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len",
        "-e", "_ws.col.Protocol"
    ]

    print("[*] Running tshark extraction...")

    with open(output_csv, "w") as आउट:
        subprocess.run(command, stdout=आउट, stderr=subprocess.DEVNULL)

    print(f"[+] CSV generated at: {output_csv}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 src/ingest.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_file = "output/transfers.csv"

    run_tshark(pcap_file, output_file)
