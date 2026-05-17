import argparse
import os
import sys

from src.ingest import run_tshark
from src.parser import load_transfers
from src.baseline import BaselineModel
from src.detector import Detector
from src.utils import load_config


def print_banner():
    print("\n======================================")
    print("  Suspicious File Transfer Detector")
    print("  Network Security Analysis Tool")
    print("======================================\n")


def run_pipeline(pcap_path: str):
    """
    Full detection pipeline.
    """

    if not os.path.exists(pcap_path):
        print(f"[ERROR] PCAP file not found: {pcap_path}")
        sys.exit(1)

    csv_path = "output/transfers.csv"

    config = load_config()

    window_size = config["window_size"]
    size_threshold = config["size_threshold_bytes"]
    frequency_threshold = config["frequency_threshold"]

    
    # STEP 1: INGEST (PCAP → CSV)
    print("[1/4] Extracting network data from PCAP...")
    run_tshark(pcap_path, csv_path)

    # ----------------------------
    # STEP 2: PARSE
    # ----------------------------
    print("[2/4] Parsing network events...")
    events = load_transfers(csv_path)

    if not events:
        print("[ERROR] No valid events parsed.")
        sys.exit(1)

    print(f"[+] Parsed events: {len(events)}")

    # ----------------------------
    # STEP 3: BASELINE
    # ----------------------------
    print("[3/4] Building baseline model...")

    baseline = BaselineModel(events, window_size=window_size).build()

    print("[+] Baseline computed:")
    print(baseline.summary())

    # ----------------------------
    # STEP 4: DETECTION
    # ----------------------------
    print("[4/4] Running anomaly detection...\n")

    detector = Detector(
        events=events,
        baseline=baseline,
        window_size=window_size,
        size_threshold=size_threshold,
        frequency_threshold=frequency_threshold
    )
    detector.run()
    detector.print_report()

    print("\n[✓] Analysis complete.")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Suspicious File Transfer Detector (Network Security Tool)"
    )

    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to PCAP file to analyze"
    )

    args = parser.parse_args()

    run_pipeline(args.pcap)


if __name__ == "__main__":
    main()
