# Pure-Python secp256k1 point arithmetic: a drop-in replacement for the four
# helpers pfcbps.py currently gets from coincurve (mul_G, mul, add, enc), plus
# rand_scalar and N. No dependency beyond the standard library.
#
# To swap it in later: in pfcbps.py, replace
#   from coincurve import PublicKey
#   ... local mul_G/mul/add/enc definitions ...
# with
#   from ec_secp256k1 import Point, N, rand_scalar, mul_G, mul, add, enc
# and change every type hint "PublicKey" to "Point". No other scheme code changes.

import secrets
from dataclasses import dataclass
from typing import Optional

# secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # field prime
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # group order


@dataclass(frozen=True)
class Point:
    x: Optional[int]  # None, None means point at infinity
    y: Optional[int]


INFINITY = Point(None, None)


def _inv(a: int, m: int) -> int:
    # modular inverse via Fermat's little theorem (m prime)
    return pow(a % m, m - 2, m)


def point_add(p1: Point, p2: Point) -> Point:
    if p1 is INFINITY or p1.x is None:
        return p2
    if p2 is INFINITY or p2.x is None:
        return p1
    if p1.x == p2.x and (p1.y + p2.y) % P == 0:
        return INFINITY
    if p1.x == p2.x and p1.y == p2.y:
        lam = (3 * p1.x * p1.x + A) * _inv(2 * p1.y, P) % P
    else:
        lam = (p2.y - p1.y) * _inv(p2.x - p1.x, P) % P
    x3 = (lam * lam - p1.x - p2.x) % P
    y3 = (lam * (p1.x - x3) - p1.y) % P
    return Point(x3, y3)


def scalar_mult(pt: Point, k: int) -> Point:
    k %= N
    result = INFINITY
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


G = Point(GX, GY)


def rand_scalar() -> int:
    return secrets.randbelow(N - 1) + 1


def mul_G(k: int) -> Point:
    return scalar_mult(G, k)


def mul(pt: Point, k: int) -> Point:
    return scalar_mult(pt, k)


def add(*pts: Point) -> Point:
    result = INFINITY
    for pt in pts:
        result = point_add(result, pt)
    return result


def enc(pt: Point) -> bytes:
    if pt is INFINITY or pt.x is None:
        raise ValueError("cannot encode point at infinity")
    prefix = b"\x02" if pt.y % 2 == 0 else b"\x03"
    return prefix + pt.x.to_bytes(32, "big")


if __name__ == "__main__":
    # Self-check against coincurve's optimized implementation, if installed.
    from coincurve import PublicKey

    for _ in range(20):
        k = rand_scalar()
        ours = enc(mul_G(k))
        theirs = PublicKey.from_secret(k.to_bytes(32, "big")).format(compressed=True)
        assert ours == theirs, f"mul_G mismatch for k={k}"

    a, b = rand_scalar(), rand_scalar()
    Pa, Pb = mul_G(a), mul_G(b)
    ours_sum = enc(add(Pa, Pb))
    theirs_pub_a = PublicKey.from_secret(a.to_bytes(32, "big"))
    theirs_pub_b = PublicKey.from_secret(b.to_bytes(32, "big"))
    theirs_sum = PublicKey.combine_keys([theirs_pub_a, theirs_pub_b]).format(compressed=True)
    assert ours_sum == theirs_sum, "add mismatch"

    c = rand_scalar()
    ours_mul = enc(mul(Pa, c))
    theirs_mul = theirs_pub_a.multiply(c.to_bytes(32, "big")).format(compressed=True)
    assert ours_mul == theirs_mul, "mul mismatch"

    print("all checks passed: ec_secp256k1 matches coincurve")
