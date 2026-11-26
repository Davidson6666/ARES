from app.core.rate_limit import SlidingWindowLimiter, client_key


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_limit_and_retry_after() -> None:
    clock = FakeClock()
    lim = SlidingWindowLimiter(limit=2, window_seconds=60, clock=clock)
    assert lim.hit("a") is None
    assert lim.hit("a") is None
    clock.now = 10
    assert lim.hit("a") == 50
    assert lim.hit("b") is None  # outra chave não é afetada
    clock.now = 60.5
    assert lim.hit("a") is None  # a primeira tentativa saiu da janela


def test_memory_is_bounded_by_max_keys() -> None:
    lim = SlidingWindowLimiter(limit=5, window_seconds=60, clock=FakeClock(), max_keys=3)
    for i in range(1000):
        lim.hit(f"ip-{i}")
    assert len(lim) == 3


def test_lru_keeps_recently_used_key() -> None:
    lim = SlidingWindowLimiter(limit=1, window_seconds=60, clock=FakeClock(), max_keys=2)
    lim.hit("ativo")
    lim.hit("x")
    assert lim.hit("ativo") is not None  # toca "ativo": "x" vira o mais antigo
    lim.hit("y")  # descarta "x", não "ativo"
    assert lim.hit("ativo") is not None


def test_ipv6_grouped_by_64() -> None:
    assert client_key("2001:db8:1:2::1") == client_key("2001:db8:1:2:ffff::9")
    assert client_key("2001:db8:1:2::1") != client_key("2001:db8:1:3::1")
    assert client_key("10.0.0.1") == "10.0.0.1"
    assert client_key(None) == "unknown"
