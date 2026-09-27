# Fig. 2 flow demo for PFCBPS.
from pfcbps import (
    CertificationOfficer,
    CloudServer,
    User,
    enc,
    verify_proxy_signature,
)

co = CertificationOfficer()
cloud = CloudServer(co.params)
params = cloud.get_params()

john = User("John", params)      # original signer / data owner
charls = User("Charls", params)  # proxy signer / data owner
eve = User("Eve", params)        # unrelated but certified third party

john.accept_certificate(co.certify(john.ID, john.pk))
charls.accept_certificate(co.certify(charls.ID, charls.pk))
eve.accept_certificate(co.certify(eve.ID, eve.pk))

w = "Charls may sign sensor readings until 2026-12-31"
delegation = john.delegate(w)
print("delegation verifies:", charls.verify_delegation(delegation, john.ID, john.pk))

m = "Temperature sensor reading: 24.7C at node 12, timestamp 2026-09-26T10:00:00Z"
sig = charls.proxy_sign(m, delegation)

valid = verify_proxy_signature(
    params, m, sig, w, john.ID, john.pk, charls.ID, charls.pk
)
print("valid proxy signature:", valid)

# --- tamper cases: all should print False ---

# altered message
print(
    "altered message:",
    verify_proxy_signature(
        params, m + " (tampered)", sig, w, john.ID, john.pk, charls.ID, charls.pk
    ),
)

# altered warrant
print(
    "altered warrant:",
    verify_proxy_signature(
        params, m, sig, w + " (tampered)", john.ID, john.pk, charls.ID, charls.pk
    ),
)

# wrong pk_J (Eve's key substituted for John's)
print(
    "wrong pk_J:",
    verify_proxy_signature(
        params, m, sig, w, john.ID, eve.pk, charls.ID, charls.pk
    ),
)

# Eve (certified, but not delegated to) signs using John's delegation intended for
# Charls; verifying against the warrant's declared proxy (Charls) must fail since
# Eve's own certificate/secret key produced the signature.
eve_sig = eve.proxy_sign(m, delegation)
print(
    "Eve signs with John's delegation:",
    verify_proxy_signature(
        params, m, eve_sig, w, john.ID, john.pk, charls.ID, charls.pk
    ),
)

# forged sigma
forged = type(sig)(sigma=(sig.sigma + 1) % (2**256), U_C=sig.U_C)
print(
    "forged sigma:",
    verify_proxy_signature(
        params, m, forged, w, john.ID, john.pk, charls.ID, charls.pk
    ),
)

# --- sizes ---
delegation_bytes = len(enc(delegation.w_J)) + 32
sig_bytes = len(enc(sig.U_C)) + 32
print(f"\ndelegation size (paper, |G|+|Zp|): 256+256 = 512 bits")
print(
    f"delegation size (actual compressed encoding): "
    f"33+32 = {delegation_bytes} bytes = {delegation_bytes * 8} bits"
)
print(f"signature size (paper, |G|+|Zp|): 256+256 = 512 bits")
print(
    f"signature size (actual compressed encoding): "
    f"33+32 = {sig_bytes} bytes = {sig_bytes * 8} bits"
)
