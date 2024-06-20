from time import perf_counter
from typing import NamedTuple, Optional


class _Checkpoint(NamedTuple):
    name: Optional[str]
    delta: float
    cumulative: float

    def __str__(self):
        return f"{self.name or 'Checkpoint'}: {self.delta:.3f} {self.cumulative:.3f}"


class PTimer(object):
    def __init__(self, name='PTimer', start_now=True):
        # Name for this timer
        self.name: str = name
        # List of checkpoints
        self.checkpoints: list[_Checkpoint] = []

        # Timer data
        self._last_time = self._start_time = None
        self._cumulative_time = 0

        if start_now:
            self.start()

    def is_started(self):
        return self._start_time is not None

    def start(self):
        if self.is_started():
            raise ValueError(f'{self.name} already started')
        self._last_time = self._start_time = perf_counter()
        self._cumulative_time = 0

    def checkpoint(self, name=None):
        if not self.is_started():
            raise ValueError(f'{self.name} not started')

        now = perf_counter()
        delta = now - self._last_time
        self._cumulative_time += delta
        self._last_time = now

        self.checkpoints.append(_Checkpoint(name, delta, self._cumulative_time))

    def __str__(self):
        return f"{self.name}\n" + "\n".join([str(c) for c in self.checkpoints])
