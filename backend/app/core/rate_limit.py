"""Limite de taxa em memória, janela deslizante (ADR 0003).

Usado por IP no login. O IP só existe em memória e some ao fim da janela;
nunca é persistido. Vale para um processo: com vários workers, cada um
conta à parte (revisar ao escalar; ver ADR 0003).

Memória limitada: no máximo ``max_keys`` chaves. Cheio, a chave usada há
mais tempo é descartada (LRU, O(1)). Isso pode zerar a contagem de quem
está há mais tempo parado, mas nunca deixa a memória crescer sem limite.
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
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        # Rotas síncronas rodam em threadpool: acesso concorrente.
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._hits)

    def hit(self, key: str) -> int | None:
        """Registra uma tentativa. Devolve ``None`` se permitida, ou os
        segundos até a próxima tentativa (para ``Retry-After``)."""
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if hits is None:
                while len(self._hits) >= self._max_keys:
                    self._hits.popitem(last=False)
                hits = self._hits[key] = deque()
            else:
                self._hits.move_to_end(key)
            while hits and hits[0] <= now - self.window:
                hits.popleft()
            if len(hits) >= self.limit:
                return max(1, math.ceil(hits[0] + self.window - now))
            hits.append(now)
            return None
