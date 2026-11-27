"""Limite de taxa em memória, janela deslizante (ADR 0003 e 0006).

Usado por IP no login e por agente na ingestão de eventos. O IP só existe em
memória e some ao fim da janela; nunca é persistido. Vale para um processo:
com vários workers, cada um conta à parte (revisar ao escalar).

Cada tentativa tem um ``cost`` (1 por padrão; na ingestão, o número de eventos
do lote). Memória limitada: no máximo ``max_keys`` chaves. Cheio, a chave usada
há mais tempo é descartada (LRU, O(1)). Isso pode zerar a contagem de quem está
há mais tempo parado, mas nunca deixa a memória crescer sem limite.
"""

import ipaddress
import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable

IPV6_PREFIX = 64


def client_key(host: str | None) -> str:
    """IPv4 por endereço; IPv6 pelo prefixo /64 (um único cliente costuma
    controlar a /64 inteira e poderia trocar de endereço a cada tentativa)."""
    if not host:
        return "unknown"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/{IPV6_PREFIX}", strict=False))
    return str(ip)


class _Window:
    __slots__ = ("hits", "total")

    def __init__(self) -> None:
        self.hits: deque[tuple[float, int]] = deque()
        self.total = 0


class SlidingWindowLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 100_000,
    ) -> None:
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._max_keys = max_keys
        self._windows: OrderedDict[str, _Window] = OrderedDict()
        # Rotas síncronas rodam em threadpool: acesso concorrente.
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._windows)

    def hit(self, key: str, cost: int = 1) -> int | None:
        """Registra ``cost`` unidades. Devolve ``None`` se permitido, ou os
        segundos até haver capacidade (para ``Retry-After``). Negado não consome."""
        now = self._clock()
        with self._lock:
            win = self._windows.get(key)
            if win is None:
                while len(self._windows) >= self._max_keys:
                    self._windows.popitem(last=False)
                win = self._windows[key] = _Window()
            else:
                self._windows.move_to_end(key)
            while win.hits and win.hits[0][0] <= now - self.window:
                win.total -= win.hits.popleft()[1]
            if win.total + cost <= self.limit:
                win.hits.append((now, cost))
                win.total += cost
                return None
            if cost > self.limit:
                return math.ceil(self.window)  # nunca cabe; espera a janela inteira
            freed = 0
            for stamp, units in win.hits:
                freed += units
                if win.total - freed + cost <= self.limit:
                    return max(1, math.ceil(stamp + self.window - now))
            return max(1, math.ceil(self.window))
