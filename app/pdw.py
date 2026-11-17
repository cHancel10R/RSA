"""Prime-Difference Window Cipher (PDW)

A symmetric, byte-oriented XOR stream cipher built from a good-prime triple,
a full-period linear congruential generator, and a static-window key derivation.

Six-phase pipeline (see project spec):

  Phase I   Select an ascending triple of "good" primes (p2^2 > p1*p3).
  Phase II  Draw 2 of the 3 primes; D = |pi - pj| is the LCG modulus.
            The leftover prime seedss X0 = pr mod D.
            Hull–Dobell parameterisation gives full-period multiplier a and
            increment c.
  Phase III Generate 50,000 LCG values X(1) ... X(50000).
  Phase IV  Sample 12 values at random positions -> S.
  Phase V   Cut S into 4 static windows of 3; global max M and min m.
  Phase VI  k = ((M mod D) mod 256);  C = P XOR k,  P = C XOR k.

Both parties holding the same parameter set Theta derive the identical key
byte k independently; encrypt and decrypt are the same XOR operation.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STREAM_LENGTH = 50_000
SAMPLE_COUNT = 12
WINDOW_SIZE = 3
DEFAULT_RNG_SEED = 2026  # documented seeded stream for the worked example


# ---------------------------------------------------------------------------
# Phase I — Good-prime selection
# ---------------------------------------------------------------------------

def is_prime(n: int) -> bool:
    """Deterministic primality test for small-to-medium integers."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def primes_up_to(limit: int) -> list[int]:
    """Return all primes <= limit via a simple sieve of Eratosthenes."""
    if limit < 2:
        return []
    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for p in range(2, int(math.isqrt(limit)) + 1):
        if sieve[p]:
            start = p * p
            sieve[start : limit + 1 : p] = b"\x00" * (((limit - start) // p) + 1)
    return [i for i in range(limit + 1) if sieve[i]]


def is_good_triple(p1: int, p2: int, p3: int) -> bool:
    """Return True when (p1, p2, p3) is a good triple: p2^2 > p1 * p3."""
    return p2 * p2 > p1 * p3


def first_good_prime_triple(limit: int = 10_000) -> tuple[int, int, int]:
    """Scan ascending consecutive prime triples and return the first good one."""
    primes = primes_up_to(limit)
    for i in range(len(primes) - 2):
        p1, p2, p3 = primes[i], primes[i + 1], primes[i + 2]
        if is_good_triple(p1, p2, p3):
            return p1, p2, p3
    raise ValueError(f"No good prime triple found among primes up to {limit}")


# ---------------------------------------------------------------------------
# Phase II — LCG parameters from the prime triple (Hull–Dobell)
# ---------------------------------------------------------------------------

def _prime_factors(n: int) -> list[int]:
    """Return the distinct prime factors of n (n >= 2)."""
    factors: list[int] = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def _lcm(a: int, b: int) -> int:
    return abs(a * b) // math.gcd(a, b)


def full_period_lcg_params(D: int) -> tuple[int, int]:
    """Return (a, c) for a full-period LCG modulo D.

    Hull–Dobell conditions:
      gcd(c, D) = 1
      a ≡ 1 (mod q) for every prime q | D
      a ≡ 1 (mod 4) whenever 4 | D

    Returns the smallest a > 1 and smallest c > 1 satisfying these.
    """
    # Collect moduli for the a ≡ 1 (mod m) congruences.
    moduli: list[int] = list(_prime_factors(D))
    if D % 4 == 0:
        moduli.append(4)

    L = 1
    for m in moduli:
        L = _lcm(L, m)

    # Smallest a > 1 with a ≡ 1 (mod L) is L + 1.
    a = L + 1

    # Smallest c > 1 coprime to D.
    c = 2
    while math.gcd(c, D) != 1:
        c += 1

    return a, c


# ---------------------------------------------------------------------------
# Phase III — Stream generation
# ---------------------------------------------------------------------------

def generate_stream(X0: int, a: int, c: int, D: int, n: int = STREAM_LENGTH) -> list[int]:
    """Iterate X(k+1) = (a * X(k) + c) mod D and emit X(1) ... X(n)."""
    stream: list[int] = []
    x = X0
    for _ in range(n):
        x = (a * x + c) % D
        stream.append(x)
    return stream


# ---------------------------------------------------------------------------
# Phase IV–V — Sampling and window statistics
# ---------------------------------------------------------------------------

def sample_and_windows(
    stream: list[int], rng: random.Random
) -> tuple[list[int], list[int], list[list[int]], list[int], list[int], int, int]:
    """Draw SAMPLE_COUNT distinct positions, collect values, compute window stats.

    Returns:
        positions, samples, windows, window_maxima, window_minima, M, m
    """
    positions = rng.sample(range(1, len(stream) + 1), SAMPLE_COUNT)
    samples = [stream[pos - 1] for pos in positions]  # positions are 1-indexed

    windows: list[list[int]] = []
    window_maxima: list[int] = []
    window_minima: list[int] = []
    for i in range(SAMPLE_COUNT // WINDOW_SIZE):
        window = samples[i * WINDOW_SIZE : (i + 1) * WINDOW_SIZE]
        windows.append(list(window))
        window_maxima.append(max(window))
        window_minima.append(min(window))

    M = max(window_maxima)
    m = min(window_minima)
    return positions, samples, windows, window_maxima, window_minima, M, m


# ---------------------------------------------------------------------------
# Phase VI — Key derivation, encrypt, decrypt
# ---------------------------------------------------------------------------

def derive_key(M: int, D: int) -> int:
    """k = ((M mod D) mod 256)."""
    return (M % D) % 256


def xor_bytes(data: bytes, k: int) -> bytes:
    """XOR every byte of data with the key byte k."""
    return bytes(b ^ k for b in data)


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------

@dataclass
class PDWParameters:
    """The shared parameter set Theta."""

    p1: int
    p2: int
    p3: int
    pair: tuple[int, int]
    D: int
    leftover: int
    X0: int
    a: int
    c: int
    rng_seed: int
    stream_length: int = STREAM_LENGTH
    sample_count: int = SAMPLE_COUNT
    window_size: int = WINDOW_SIZE


@dataclass
class PDWDerivation:
    """Full derivation trace: parameters, stream, samples, windows, key."""

    params: PDWParameters
    positions: list[int]
    samples: list[int]
    windows: list[list[int]]
    window_maxima: list[int]
    window_minima: list[int]
    M: int
    m: int
    K: int
    k: int
    stream: list[int] = field(repr=False)


class PDWCipher:
    """PDW symmetric cipher.

    Construct with a prime triple and RNG seed; both parties holding the same
    values independently derive the identical key byte k.
    """

    def __init__(
        self,
        primes: tuple[int, int, int] | None = None,
        rng_seed: int = DEFAULT_RNG_SEED,
        stream_length: int = STREAM_LENGTH,
    ) -> None:
        if primes is None:
            primes = first_good_prime_triple()
        p1, p2, p3 = primes
        if not is_good_triple(p1, p2, p3):
            raise ValueError(f"({p1}, {p2}, {p3}) is not a good prime triple")
        if not (is_prime(p1) and is_prime(p2) and is_prime(p3)):
            raise ValueError("All three values must be prime")

        rng = random.Random(rng_seed)

        # Phase II — draw 2 of 3 primes uniformly at random (unordered pair).
        pair = tuple(rng.sample([p1, p2, p3], 2))
        D = abs(pair[0] - pair[1])
        leftover = next(p for p in (p1, p2, p3) if p not in pair)
        X0 = leftover % D
        a, c = full_period_lcg_params(D)

        # Phase III — generate the stream X(1) ... X(stream_length).
        stream = generate_stream(X0, a, c, D, stream_length)

        # Phase IV–V — sample and compute window statistics.
        (
            positions,
            samples,
            windows,
            window_maxima,
            window_minima,
            M,
            m,
        ) = sample_and_windows(stream, rng)

        # Phase VI — key derivation.
        K = M % D
        k = K % 256

        self.params = PDWParameters(
            p1=p1,
            p2=p2,
            p3=p3,
            pair=pair,
            D=D,
            leftover=leftover,
            X0=X0,
            a=a,
            c=c,
            rng_seed=rng_seed,
            stream_length=stream_length,
        )
        self._positions = positions
        self._samples = samples
        self._windows = windows
        self._window_maxima = window_maxima
        self._window_minima = window_minima
        self._M = M
        self._m = m
        self._K = K
        self._k = k
        self._stream = stream

    # -- derived values -----------------------------------------------------

    @property
    def key(self) -> int:
        """Key byte k."""
        return self._k

    @property
    def derivation(self) -> PDWDerivation:
        return PDWDerivation(
            params=self.params,
            positions=list(self._positions),
            samples=list(self._samples),
            windows=[list(w) for w in self._windows],
            window_maxima=list(self._window_maxima),
            window_minima=list(self._window_minima),
            M=self._M,
            m=self._m,
            K=self._K,
            k=self._k,
            stream=list(self._stream),
        )

    # -- encrypt / decrypt --------------------------------------------------

    def encrypt(self, plaintext: bytes | str) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        return xor_bytes(plaintext, self._k)

    def decrypt(self, ciphertext: bytes | str) -> bytes:
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode("utf-8")
        return xor_bytes(ciphertext, self._k)


# ---------------------------------------------------------------------------
# Convenience: derive a cipher directly from a parameter set (Theta)
# ---------------------------------------------------------------------------

def cipher_from_params(params: PDWParameters, rng_seed: int | None = None) -> PDWCipher:
    """Re-construct a PDWCipher from a PDWParameters set.

    The stream, samples and key are re-derived deterministically from Theta.
    """
    seed = rng_seed if rng_seed is not None else params.rng_seed
    return PDWCipher(primes=(params.p1, params.p2, params.p3), rng_seed=seed, stream_length=params.stream_length)


def worked_example() -> PDWCipher:
    """Return the cipher for the spec's worked example.

    Triple (193, 233, 257), RNG seed 2026.
    Expected: D = 40, X0 = 17, a = 21, c = 3, k = 38.
    """
    return PDWCipher(primes=(193, 233, 257), rng_seed=DEFAULT_RNG_SEED)