from typing import List, Dict
from collections import defaultdict
import statistics

from src.parser import TransferEvent


class BaselineModel:
    """
    Computes normal network behavior baseline.
    """

    def __init__(self, events: List[TransferEvent], window_size: int = 60):
        self.events = events
        self.window_size = window_size  # seconds (1 minute default)

        # computed values
        self.avg_size = 0
        self.max_size_threshold = 0

        self.avg_frequency = 0
        self.max_frequency_threshold = 0

        # internal structures
        self._windowed_counts = []

    def build(self):
        """
        Build baseline statistics from event data.
        """

        if not self.events:
            return self

        sizes = [e.bytes for e in self.events if e.bytes is not None]

        # -------------------------
        # 1. SIZE BASELINE
        # -------------------------
        self.avg_size = statistics.mean(sizes) if sizes else 0

        std_size = statistics.stdev(sizes) if len(sizes) > 1 else 0

        self.max_size_threshold = self.avg_size + (2 * std_size)

        # -------------------------
        # 2. FREQUENCY BASELINE
        # -------------------------
        window_counts = self._compute_window_frequencies()

        self._windowed_counts = window_counts

        self.avg_frequency = statistics.mean(window_counts) if window_counts else 0

        std_freq = statistics.stdev(window_counts) if len(window_counts) > 1 else 0

        self.max_frequency_threshold = self.avg_frequency + (2 * std_freq)

        return self

    def _compute_window_frequencies(self) -> List[int]:
        """
        Groups events into 1-minute windows and counts them.
        """

        windows = defaultdict(int)

        for e in self.events:
            window_key = int(e.timestamp // self.window_size)
            windows[window_key] += 1

        return list(windows.values())

    def summary(self) -> Dict:
        """
        Returns baseline summary for debugging.
        """

        return {
            "avg_size": self.avg_size,
            "max_size_threshold": self.max_size_threshold,
            "avg_frequency": self.avg_frequency,
            "max_frequency_threshold": self.max_frequency_threshold
        }


# Quick test
if __name__ == "__main__":
    from parser import load_transfers

    events = load_transfers("../output/transfers.csv")

    baseline = BaselineModel(events).build()

    print(baseline.summary())