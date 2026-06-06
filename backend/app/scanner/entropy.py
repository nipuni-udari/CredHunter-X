from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_high_entropy(value: str, minimum_length: int = 20, threshold: float = 4.0) -> bool:
    return len(value) >= minimum_length and shannon_entropy(value) >= threshold
