
import csv
from typing import List, Dict, Any, Optional


class TransferEvent:

    def __init__(self, timestamp: float, src_ip: str, dst_ip: str, protocol: str, bytes_size: int):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.bytes = bytes_size

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "bytes": self.bytes
        }


def safe_int(value: Optional[str], default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value: Optional[str], default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def load_transfers(csv_path: str) -> List[TransferEvent]:


    events: List[TransferEvent] = []

    with open(csv_path, "r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            try:
                timestamp = safe_float(row.get("frame.time_epoch"))
                src_ip = row.get("ip.src")
                dst_ip = row.get("ip.dst")
                protocol = row.get("_ws.col.Protocol", "UNKNOWN")
                bytes_size = safe_int(row.get("frame.len"))

                
                if not src_ip or not dst_ip:
                    continue

                event = TransferEvent(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    bytes_size=bytes_size
                )

                events.append(event)

            except Exception:
                
                continue

    return events


# for quick manuall testing
if __name__ == "__main__":
    data = load_transfers("../output/transfers.csv")

    print(f"Loaded events: {len(data)}")


    for e in data[:3]:
        print(e.to_dict())
