# PFCBPS: pairing-free certificate-based proxy signature (Verma et al., Inf. Sci. 518 (2020))
# Curve: secp256k1, generator P is coincurve's implicit base point, group order N below.
# (A from-scratch pure-Python implementation of the same point arithmetic is kept in
# ec_secp256k1.py, cross-checked against coincurve, but is not wired in here.)
import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional

from coincurve import PublicKey

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def rand_scalar() -> int:
    return secrets.randbelow(N - 1) + 1


def mul_G(k: int) -> PublicKey:
    # k*P
    return PublicKey.from_secret((k % N).to_bytes(32, "big"))


def mul(pt: PublicKey, k: int) -> PublicKey:
    # k*pt
    return pt.multiply((k % N).to_bytes(32, "big"))


def add(*pts: PublicKey) -> PublicKey:
    return PublicKey.combine_keys(list(pts))


def enc(pt: PublicKey) -> bytes:
    return pt.format(compressed=True)


def H(tag: bytes, *parts) -> int:
    # domain-separated SHA-256 over length-prefixed parts, reduced mod N
    h = hashlib.sha256()
    h.update(tag)
    for part in parts:
        if isinstance(part, PublicKey):
            b = enc(part)
        elif isinstance(part, str):
            b = part.encode("utf-8")
        elif isinstance(part, bytes):
            b = part
        else:
            raise TypeError(f"unsupported hash input type: {type(part)}")
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    return int.from_bytes(h.digest(), "big") % N


def H0(ID: str, pk: PublicKey) -> int:
    return H(b"H0", ID, pk)


def H1(w: str, ID_J: str, pk_J: PublicKey) -> int:
    return H(b"H1", w, ID_J, pk_J)


def H2(w: str, m: str, ID_C: str, pk_C: PublicKey, U_C: PublicKey) -> int:
    return H(b"H2", w, m, ID_C, pk_C, U_C)


@dataclass
class Params:
    pk_CO: PublicKey
    curve: str = "secp256k1"


@dataclass
class Certificate:
    R: PublicKey
    t: int


@dataclass
class Delegation:
    w: str
    w_J: PublicKey
    W_J: int


@dataclass
class ProxySignature:
    sigma: int
    U_C: PublicKey


class CertificationOfficer:
    def __init__(self):
        # CB-ParGen
        self.s = rand_scalar()
        self.params = Params(pk_CO=mul_G(self.s))

    def certify(self, ID: str, pk: PublicKey) -> Certificate:
        # CB-Certification
        r = rand_scalar()
        R = mul_G(r)
        t = (r + self.s * H0(ID, pk)) % N
        return Certificate(R=R, t=t)


class CloudServer:
    # in-memory stand-in for the paper's cloud server: just stores/serves public params
    def __init__(self, params: Params):
        self.params = params

    def get_params(self) -> Params:
        return self.params


class User:
    def __init__(self, ID: str, params: Params):
        # CB-KeyGeneration
        self.ID = ID
        self.params = params
        self.s_ID = rand_scalar()
        self.pk = mul_G(self.s_ID)
        self.cert: Optional[Certificate] = None

    def accept_certificate(self, cert: Certificate) -> None:
        lhs = mul_G(cert.t)
        rhs = add(cert.R, mul(self.params.pk_CO, H0(self.ID, self.pk)))
        if enc(lhs) != enc(rhs):
            raise ValueError("invalid certificate")
        self.cert = cert

    def delegate(self, w: str) -> Delegation:
        # CB-Delegation (original signer, e.g. John)
        if self.cert is None:
            raise ValueError("no certificate accepted")
        k_J = rand_scalar()
        w_J = add(self.cert.R, mul_G(k_J))
        W_J = (self.cert.t + k_J + self.s_ID * H1(w, self.ID, self.pk)) % N
        return Delegation(w=w, w_J=w_J, W_J=W_J)

    def verify_delegation(self, d: Delegation, ID_J: str, pk_J: PublicKey) -> bool:
        # CB-DelVerification (proxy signer, e.g. Charls)
        lhs = mul_G(d.W_J)
        rhs = add(
            d.w_J,
            mul(self.params.pk_CO, H0(ID_J, pk_J)),
            mul(pk_J, H1(d.w, ID_J, pk_J)),
        )
        return enc(lhs) == enc(rhs)

    def proxy_sign(self, m: str, d: Delegation) -> ProxySignature:
        # CB-ProxySigning (proxy signer, e.g. Charls); requires own certificate
        if self.cert is None:
            raise ValueError("no certificate accepted")
        k_C = rand_scalar()
        U_C = add(d.w_J, self.cert.R, mul_G(k_C))
        # NOTE: paper's Fig. 5 step 3 mislabels this hash as H1 (typo); it is H2,
        # as defined in Sec. 3 step 6 and used in Theorem 1's correctness proof.
        h2 = H2(d.w, m, self.ID, self.pk, U_C)
        sigma = (d.W_J + k_C + self.cert.t + h2 * self.s_ID) % N
        return ProxySignature(sigma=sigma, U_C=U_C)


def verify_proxy_signature(
    params: Params,
    m: str,
    sig: ProxySignature,
    w: str,
    ID_J: str,
    pk_J: PublicKey,
    ID_C: str,
    pk_C: PublicKey,
) -> bool:
    # CB-PSignVerification (end user); uses only public data
    h0J = H0(ID_J, pk_J)
    h0C = H0(ID_C, pk_C)
    h1 = H1(w, ID_J, pk_J)
    h2 = H2(w, m, ID_C, pk_C, sig.U_C)
    lhs = mul_G(sig.sigma)
    rhs = add(
        sig.U_C,
        mul(params.pk_CO, (h0J + h0C) % N),
        mul(pk_J, h1),
        mul(pk_C, h2),
    )
    return enc(lhs) == enc(rhs)
