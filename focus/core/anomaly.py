"""Streaming anomaly detection for network throughput.

The original project printed a RandomForest prediction keyed on
``elapsed_time`` but detected surges with a fixed ``inbound - outbound > 2``
rule. That model cannot generalise across runs (elapsed time restarts at zero
every session), so v2 uses a robust online detector instead: an exponentially
weighted mean/variance baseline and a sustained z-score. It needs no training
data, adapts to the machine it runs on, and is explainable in the UI.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass

CALM = "calm"
ELEVATED = "elevated"
SURGE = "surge"

_SEVERITY = {CALM: 0, ELEVATED: 1, SURGE: 2}


@dataclass(frozen=True)
class Verdict:
    value: float
    baseline: float
    sigma: float
    z: float
    level: str
    streak: int

    @property
    def residual(self) -> float:
        return self.value - self.baseline


class RollingDetector:
    """Two-timescale deviation detector.

    A slow EWMA tracks what "normal" looks like; a fast EWMA tracks recent
    variability. The z-score measures how far the current value is from the
    *slow* baseline relative to recent noise, so a step change stays visible
    until the slow baseline catches up — which is exactly when a human should
    be alerted.
    """

    def __init__(
        self,
        *,
        alpha_slow: float = 0.02,
        alpha_fast: float = 0.05,
        warmup: int = 5,
        z_elevated: float = 2.0,
        z_surge: float = 2.5,
        sustain: int = 2,
        sigma_floor: float = 0.05,
        hold: int = 4,
    ) -> None:
        self.alpha_slow = alpha_slow
        self.alpha_fast = alpha_fast
        self.warmup = warmup
        self.z_elevated = z_elevated
        self.z_surge = z_surge
        self.sustain = sustain
        self.sigma_floor = sigma_floor
        self.hold = hold
        self._slow_mean: float | None = None
        self._fast_var = 0.0
        self._count = 0
        self._streak = 0
        self._hold = 0
        self._history: deque[float] = deque(maxlen=120)

    @property
    def baseline(self) -> float:
        return self._slow_mean or 0.0

    @property
    def history(self) -> list[float]:
        return list(self._history)

    def update(self, value: float) -> Verdict:
        value = max(0.0, float(value))
        self._history.append(value)

        if self._slow_mean is None:
            self._slow_mean = value
            self._count = 1
            return Verdict(value, value, self.sigma_floor, 0.0, CALM, 0)

        previous_mean = self._slow_mean
        self._count += 1
        self._slow_mean = self.alpha_slow * value + (1 - self.alpha_slow) * previous_mean

        # Fast variability around the slow baseline.
        deviation = value - previous_mean
        self._fast_var = self.alpha_fast * deviation ** 2 + (1 - self.alpha_fast) * self._fast_var

        sigma = max(math.sqrt(self._fast_var), self.sigma_floor)
        z = (value - self._slow_mean) / sigma

        if self._count <= self.warmup:
            return Verdict(value, self._slow_mean, sigma, z, CALM, self._streak)

        if z >= self.z_surge:
            self._streak += 1
        else:
            self._streak = 0

        if z >= self.z_surge and self._streak >= self.sustain:
            level = SURGE
            self._hold = self.hold
        elif self._hold > 0:
            level = SURGE
            self._hold -= 1
        elif z >= self.z_elevated:
            level = ELEVATED
        else:
            level = CALM

        return Verdict(value, self._slow_mean, sigma, z, level, self._streak)


def combine(inbound: Verdict, outbound: Verdict) -> tuple[str, Verdict]:
    """The overall state is the more severe of the two directions."""
    if _SEVERITY[outbound.level] > _SEVERITY[inbound.level]:
        return outbound.level, outbound
    return inbound.level, inbound


def demo_offset(index: int) -> tuple[float, float]:
    """Deterministic synthetic spike used by ``focus dashboard --demo``.

    Inbound jumps at t+8s and stays elevated for ~12s, which is long enough
    to carry the surge detector past its warmup and sustain rule even when
    ticks run slower than one second; outbound adds a smaller bump later.
    """
    inbound = 0.0
    outbound = 0.0
    if 8 <= index < 20:
        inbound = 50.0
    if 10 <= index < 16:
        outbound = 12.0
    return inbound, outbound
