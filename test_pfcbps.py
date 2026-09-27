import pytest

from pfcbps import (
    CertificationOfficer,
    CloudServer,
    User,
    verify_proxy_signature,
)

WARRANT = "Charls may sign sensor readings until 2026-12-31"
MESSAGE = "Temperature sensor reading: 24.7C at node 12"


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


def test_certificate_accepted(setup):
    co, params, john, charls = setup
    assert john.cert is not None
    assert charls.cert is not None


def test_tampered_certificate_rejected(setup):
    co, params, john, charls = setup
    mallory = User("Mallory", params)
    cert = co.certify(mallory.ID, mallory.pk)
    cert.t = (cert.t + 1) % (2**256)
    with pytest.raises(ValueError):
        mallory.accept_certificate(cert)


def test_delegation_verifies(setup):
    co, params, john, charls = setup
    d = john.delegate(WARRANT)
    assert charls.verify_delegation(d, john.ID, john.pk) is True


def test_delegation_wrong_warrant_fails(setup):
    co, params, john, charls = setup
    d = john.delegate(WARRANT)
    d.w = WARRANT + " (tampered)"
    assert charls.verify_delegation(d, john.ID, john.pk) is False


def test_delegation_wrong_pkJ_fails(setup):
    co, params, john, charls = setup
    d = john.delegate(WARRANT)
    eve = User("Eve", params)
    assert charls.verify_delegation(d, john.ID, eve.pk) is False


@pytest.mark.parametrize("run", range(5))
def test_proxy_signature_correctness(setup, run):
    co, params, john, charls = setup
    d = john.delegate(WARRANT)
    assert charls.verify_delegation(d, john.ID, john.pk)
    sig = charls.proxy_sign(MESSAGE, d)
    assert verify_proxy_signature(
        params, MESSAGE, sig, WARRANT, john.ID, john.pk, charls.ID, charls.pk
    ) is True


def test_modified_message_fails(setup):
    co, params, john, charls = setup
    d = john.delegate(WARRANT)
    sig = charls.proxy_sign(MESSAGE, d)
    assert verify_proxy_signature(
        params, MESSAGE + "x", sig, WARRANT, john.ID, john.pk, charls.ID, charls.pk
    ) is False


def test_modified_warrant_fails(setup):
    co, params, john, charls = setup
    d = john.delegate(WARRANT)
    sig = charls.proxy_sign(MESSAGE, d)
    assert verify_proxy_signature(
        params, MESSAGE, sig, WARRANT + "x", john.ID, john.pk, charls.ID, charls.pk
    ) is False


def test_modified_sigma_fails(setup):
    co, params, john, charls = setup
    d = john.delegate(WARRANT)
    sig = charls.proxy_sign(MESSAGE, d)
    sig.sigma = (sig.sigma + 1) % (2**256)
    assert verify_proxy_signature(
        params, MESSAGE, sig, WARRANT, john.ID, john.pk, charls.ID, charls.pk
    ) is False


def test_modified_UC_fails(setup):
    co, params, john, charls = setup
    d = john.delegate(WARRANT)
    sig = charls.proxy_sign(MESSAGE, d)
    other_sig = charls.proxy_sign(MESSAGE, d)
    sig.U_C = other_sig.U_C
    assert verify_proxy_signature(
        params, MESSAGE, sig, WARRANT, john.ID, john.pk, charls.ID, charls.pk
    ) is False


def test_replaced_pkC_fails(setup):
    co, params, john, charls = setup
    d = john.delegate(WARRANT)
    sig = charls.proxy_sign(MESSAGE, d)
    eve = User("Eve", params)
    assert verify_proxy_signature(
        params, MESSAGE, sig, WARRANT, john.ID, john.pk, charls.ID, eve.pk
    ) is False


def test_replaced_pkJ_fails(setup):
    co, params, john, charls = setup
    d = john.delegate(WARRANT)
    sig = charls.proxy_sign(MESSAGE, d)
    eve = User("Eve", params)
    assert verify_proxy_signature(
        params, MESSAGE, sig, WARRANT, john.ID, eve.pk, charls.ID, charls.pk
    ) is False
