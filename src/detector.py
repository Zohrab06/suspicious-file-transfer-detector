from collections import defaultdict
from typing import List, Dict, Any

from src.parser import TransferEvent
from src.baseline import BaselineModel


class SuspiciousEvent:
    """
    Represents a detected anomaly.
    """

    def __init__(self, src_ip, dst_ip, window, reasons, total_bytes, count):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.window = window
        self.reasons = reasons
        self.total_bytes = total_bytes
        self.count = count

    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "window": self.window,
            "reasons": self.reasons,
            "total_bytes": self.total_bytes,
            "count": self.count
        }


class Detector:
    """
    Detects suspicious file transfer activity using baseline thresholds.
    """

    def __init__(self, events: List[TransferEvent], baseline: BaselineModel, window_size: int = 60):
        self.events = events
        self.baseline = baseline
        self.window_size = window_size

        self.suspicious: List[SuspiciousEvent] = []

    def run(self) -> List[SuspiciousEvent]:
        """
        Main detection pipeline.
        """

        # Step 1 — group events by window + flow
        grouped = self._group_events()

        # Step 2 — analyze each group
        for key, items in grouped.items():
            src_ip, dst_ip, window = key

            total_bytes = sum(e.bytes for e in items)
            count = len(items)

            reasons = []

            # -----------------------------
            # RULE 1: SIZE ANOMALY
            # -----------------------------
            if total_bytes > self.baseline.max_size_threshold:
                reasons.append("High transfer volume detected")

            # -----------------------------
            # RULE 2: FREQUENCY ANOMALY
            # -----------------------------
            if count > self.baseline.max_frequency_threshold:
                reasons.append("Abnormal transfer frequency")

            # -----------------------------
            # RULE 3: BURST PATTERN
            # -----------------------------
            large_events = [
                e for e in items
                if e.bytes > self.baseline.max_size_threshold
            ]

            if len(large_events) >= 2:
                reasons.append("Multiple large transfers in short window")

            # If suspicious → store result
            if reasons:
                self.suspicious.append(
                    SuspiciousEvent(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        window=window,
                        reasons=reasons,
                        total_bytes=total_bytes,
                        count=count
                    )
                )

        return self.suspicious

    def _group_events(self) -> Dict:
        """
        Group by:
        (src_ip, dst_ip, time_window)
        """

        grouped = defaultdict(list)

        for e in self.events:
            window = int(e.timestamp // self.window_size)

            key = (e.src_ip, e.dst_ip, window)
            grouped[key].append(e)

        return grouped

    def print_report(self):
        """
        Human-readable SOC-style output.
        """

        print("\n=== SUSPICIOUS ACTIVITY REPORT ===\n")

        if not self.suspicious:
            print("No suspicious activity detected.")
            return

        for s in self.suspicious:
            print(f"Source IP: {s.src_ip}")
            print(f"Destination IP: {s.dst_ip}")
            print(f"Window: {s.window}")
            print(f"Total Bytes: {s.total_bytes}")
            print(f"Event Count: {s.count}")
            print("Reasons:")

            for r in s.reasons:
                print(f" - {r}")

            print("-" * 40)


# Quick test
if __name__ == "__main__":
    from parser import load_transfers
    from baseline import BaselineModel

    events = load_transfers("../output/transfers.csv")
    baseline = BaselineModel(events).build()

    detector = Detector(events, baseline)
    detector.run()
    detector.print_report()