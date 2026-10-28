"""Response-time summaries.

Percentiles use the nearest-rank method: every value reported is one that
was actually measured, which is easier to check against a capture by hand
than an interpolated figure, and honest about small samples (with five
replies, p95 is simply the slowest).
"""

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Summary:
    count: int
    p50: float = None
    p95: float = None
    p99: float = None
    max: float = None

    @classmethod
    def of(cls, values):
        values = sorted(values)
        if not values:
            return cls(0)
        return cls(len(values), percentile(values, 50), percentile(values, 95), percentile(values, 99), values[-1])


def percentile(sorted_values, q):
    """The nearest-rank q-th percentile of an already sorted, non-empty list."""
    rank = max(1, math.ceil(q / 100 * len(sorted_values)))
    return sorted_values[rank - 1]
