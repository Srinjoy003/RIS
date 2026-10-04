# Attacks on PFCBPS, in two groups.
# 1. Forgeries that WORK: each test PASSES because the scheme accepts the forgery.
#    H0 does not hash R_i and H1 does not hash w_J, so an attacker can pick the
#    secret scalar first and solve for the point that balances the check.
# 2. Attacks the scheme RESISTS: each test PASSES because the scheme rejects them.
import pytest

from pfcbps import (
    N,
    H0,
    H1,
    H2,
    Certificate,
    CertificationOfficer,
    CloudServer,
    Delegation,
    ProxySignature,
    User,
    add,
    mul,
    mul_G,
    rand_scalar,
    verify_proxy_signature,
)

FORGED_WARRANT = "Charls may sign anything, forever"
WARRANT = "Charls may sign sensor readings until 2026-12-31"
MESSAGE = "Valve 7: pressure normal"


def neg(pt):
    return mul(pt, N - 1)


# --- attacker code: public values only (plus the signer's own key where noted) ---


def forge_certificate(pk_CO, ID, pk):
    t = rand_scalar()
    R = add(mul_G(t), neg(mul(pk_CO, H0(ID, pk))))
    return Certificate(R=R, t=t)


def forge_delegation(pk_CO, ID_J, pk_J, w):
    W = rand_scalar()
    w_J = add(
        mul_G(W),
        neg(mul(pk_CO, H0(ID_J, pk_J))),
        neg(mul(pk_J, H1(w, ID_J, pk_J))),
    )
    return Delegation(w=w, w_J=w_J, W_J=W)


def forge_signature(pk_CO, ID_J, pk_J, ID_C, pk_C, s_C, w, m):
    # s_C is the signer's own private key; nothing from John or the CO is used
    a = rand_scalar()
    U = add(
        mul_G(a),
        neg(mul(pk_CO, (H0(ID_J, pk_J) + H0(ID_C, pk_C)) % N)),
        neg(mul(pk_J, H1(w, ID_J, pk_J))),
    )
    sigma = (a + H2(w, m, ID_C, pk_C, U) * s_C) % N
    return ProxySignature(sigma=sigma, U_C=U)


def forget_secrets(co, *users):
    # any accidental use of a secret now crashes instead of silently helping
    co.s = None
    for u in users:
        u.s_ID = None
        u.cert = None


@pytest.fixture
def setup():
    co = CertificationOfficer()
    cloud = CloudServer(co.params)
    params = cloud.get_params()
    john = User("John", params)
    charls = User("Charls", params)
    john.accept_certificate(co.certify(john.ID, john.pk))
    charls.accept_certificate(co.certify(charls.ID, charls.pk))
    return co, params, john, charls


# --- forgeries that work ---


def test_forged_certificate_accepted(setup):
    co, params, john, charls = setup
    mallory = User("Mallory", params)  # never certified by the CO
    forget_secrets(co, john, charls)
    mallory.accept_certificate(forge_certificate(params.pk_CO, mallory.ID, mallory.pk))
    assert mallory.cert is not None


def test_forged_delegation_accepted(setup):
    co, params, john, charls = setup
    forget_secrets(co, john)
    d = forge_delegation(params.pk_CO, john.ID, john.pk, FORGED_WARRANT)
    assert charls.verify_delegation(d, john.ID, john.pk) is True


def test_honest_signing_with_forged_delegation_verifies(setup):
    co, params, john, charls = setup
    forget_secrets(co, john)
    d = forge_delegation(params.pk_CO, john.ID, john.pk, FORGED_WARRANT)
    sig = charls.proxy_sign(MESSAGE, d)
    assert verify_proxy_signature(
        params, MESSAGE, sig, FORGED_WARRANT, john.ID, john.pk, charls.ID, charls.pk
    ) is True


def test_proxy_signs_without_delegation(setup):
    co, params, john, charls = setup
    s_C = charls.s_ID
    forget_secrets(co, john, charls)
    sig = forge_signature(
        params.pk_CO, john.ID, john.pk, charls.ID, charls.pk, s_C, FORGED_WARRANT, MESSAGE
    )
    assert verify_proxy_signature(
        params, MESSAGE, sig, FORGED_WARRANT, john.ID, john.pk, charls.ID, charls.pk
    ) is True


def test_uncertified_user_signs_for_john(setup):
    co, params, john, charls = setup
    mallory = User("Mallory", params)  # no certificate, no delegation
    s_M = mallory.s_ID
    forget_secrets(co, john, charls, mallory)
    sig = forge_signature(
        params.pk_CO, john.ID, john.pk, mallory.ID, mallory.pk, s_M, FORGED_WARRANT, MESSAGE
    )
    assert verify_proxy_signature(
        params, MESSAGE, sig, FORGED_WARRANT, john.ID, john.pk, mallory.ID, mallory.pk
    ) is True


def test_forgery_after_public_key_replacement(setup):
    co, params, john, charls = setup
    forget_secrets(co, john, charls)
    s_fake = rand_scalar()
    pk_fake = mul_G(s_fake)  # presented to the verifier as Charls's key
    sig = forge_signature(
        params.pk_CO, john.ID, john.pk, charls.ID, pk_fake, s_fake, FORGED_WARRANT, MESSAGE
    )
    assert verify_proxy_signature(
        params, MESSAGE, sig, FORGED_WARRANT, john.ID, john.pk, charls.ID, pk_fake
    ) is True


def test_replayed_signature_accepted_again(setup):
    # verification keeps no state, so a captured (m, sigma, U_C) verifies every time it is resent
    co, params, john, charls = setup
    sig = charls.proxy_sign(MESSAGE, john.delegate(WARRANT))
    for _ in range(3):
        assert verify_proxy_signature(
            params, MESSAGE, sig, WARRANT, john.ID, john.pk, charls.ID, charls.pk
        ) is True


# --- attacks the scheme resists ---


def test_resists_forgery_for_real_key_without_its_secret(setup):
    # the Schnorr layer holds: forging for Charls's real key needs s_C
    co, params, john, charls = setup
    sig = forge_signature(
        params.pk_CO, john.ID, john.pk, charls.ID, charls.pk, rand_scalar(), FORGED_WARRANT, MESSAGE
    )
    assert verify_proxy_signature(
        params, MESSAGE, sig, FORGED_WARRANT, john.ID, john.pk, charls.ID, charls.pk
    ) is False


def test_resists_stolen_delegation_without_proxy_key(setup):
    # Eve intercepts John's real delegation but cannot use it to sign as Charls
    co, params, john, charls = setup
    eve = User("Eve", params)
    eve.accept_certificate(co.certify(eve.ID, eve.pk))
    d = john.delegate(WARRANT)
    sig = eve.proxy_sign(MESSAGE, d)
    assert verify_proxy_signature(
        params, MESSAGE, sig, WARRANT, john.ID, john.pk, charls.ID, charls.pk
    ) is False


def test_resists_signature_malleability(setup):
    # shifting sigma and U_C by the same amount changes h2, so the result fails
    co, params, john, charls = setup
    sig = charls.proxy_sign(MESSAGE, john.delegate(WARRANT))
    c = rand_scalar()
    mauled = ProxySignature(sigma=(sig.sigma + c) % N, U_C=add(sig.U_C, mul_G(c)))
    assert verify_proxy_signature(
        params, MESSAGE, mauled, WARRANT, john.ID, john.pk, charls.ID, charls.pk
    ) is False


def test_resists_role_swap(setup):
    # a real signature cannot be passed off with John and Charls's roles swapped
    co, params, john, charls = setup
    sig = charls.proxy_sign(MESSAGE, john.delegate(WARRANT))
    assert verify_proxy_signature(
        params, MESSAGE, sig, WARRANT, charls.ID, charls.pk, john.ID, john.pk
    ) is False


def test_resists_reusing_signature_on_new_message(setup):
    # a captured signature cannot be attached to a different reading
    co, params, john, charls = setup
    sig = charls.proxy_sign(MESSAGE, john.delegate(WARRANT))
    assert verify_proxy_signature(
        params, "Valve 7: pressure critical", sig, WARRANT, john.ID, john.pk, charls.ID, charls.pk
    ) is False
