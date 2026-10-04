# PFCBPS Seminar Script

One short paragraph per slide of PFCBPS_Seminar.pptx (24 slides), about 15 minutes spoken. Say the main point and leave the rest of each slide for the audience to read.

## Background and setup (slides 1–7)

### 1 · Title

Good morning. I'll be presenting PFCBPS, a pairing-free certificate-based proxy signature scheme for Industrial IoT, by Verma and co-authors, published in Information Sciences in 2020. I'll cover the idea, the protocol, the security claims, and what we found when we implemented it.

### 2 · The delegation dilemma

In a factory or power grid, sensors produce readings that directly drive machines, so every reading has to be signed. A supervisor can't sign each packet by hand. But copying the supervisor's private key onto every sensor is dangerous: capture one sensor and you have the key for the whole plant. So we need a way to delegate signing rights without sharing the key. The four points on the right are what the scheme has to achieve.

### 3 · Standard vs. proxy signatures

With a normal signature, only Alice can sign, and Bob verifies with her public key. With a proxy signature, John gives Charls a delegation token bound to a warrant, which says what Charls may sign and for how long. Charls signs with that token plus his own key. The verifier can then confirm both that John delegated and that Charls signed.

### 4 · Comparing public-key paradigms

Here's why the paper picks certificate-based cryptography. Traditional PKI needs certificate checks on every use. In identity-based cryptography, the authority holds everyone's private keys. Certificateless schemes are open to key-replacement attacks. Certificate-based cryptography avoids all three. The gap is that earlier certificate-based proxy schemes relied on pairings, which are slow on IoT hardware. This paper claims the first one without pairings.

### 5 · System model

Four entities take part in the protocol. The Certification Officer sets up the system and certifies users. John, the supervisor, is the original signer who delegates. Charls, the sensor, is the proxy signer who signs readings. And the verifier checks signatures using only public keys. There's also a cloud server, but it only stores and relays data. The strip at the bottom shows the order: certify, delegate, sign, verify.

### 6 · Elliptic curves and the ECDLP

All we need is one fact: multiplying a point P by a number k is fast, but given P and kP, recovering k is infeasible. That's the elliptic-curve discrete logarithm problem, and on a 256-bit curve it gives about 128-bit security. Every equation that follows comes down to that.

### 7 · The seven algorithms

The scheme has seven algorithms in three phases: setup and certification, then delegation, then signing and verification. Setup happens once per user, delegation once per warrant, and signing once per reading. I'll go through them quickly.

## The protocol (slides 8–13)

### 8 · Algorithms 1 & 2

Setup is simple. The CO picks a master secret and publishes its public version. Then each user, John and Charls, makes their own key pair. *(Point at the right-hand card.)* The key point: the CO never sees anyone's private key, so unlike identity-based schemes there's no key escrow.

### 9 · Algorithm 3: Certification

Next, the CO certifies each user. *(Point at the formula for t.)* The certificate secret, t, is a fresh random value plus the CO's master secret times a hash of the user's ID and public key. Remember that shape, random value plus secret key times a hash, because every secret in this scheme follows it. On the right, the user checks it. The trick is to multiply by P: each piece turns into something public, the random value into R and the master secret into the CO's public key. Every check in the scheme works the same way.

### 10 · Algorithm 4: Delegation

Now John delegates. He builds one secret number, W-J, from three parts. *(Point at each part.)* First, his certificate secret, which carries the CO's approval. Second, a fresh random value that hides his secrets from Charls. Third, his private key times a hash of the warrant, which is his signature on the warrant. It's the same pattern as before. He sends this to Charls along with the warrant.

### 11 · Algorithm 5: Delegation check

Charls doesn't accept it blindly. *(Point at the check.)* He runs one check using only public values: John's delegation point, the CO's public key and John's public key. It's the same trick: multiply W-J by P and each of its three parts becomes something public. The derivation is on the right. It costs three scalar multiplications and no pairings.

### 12 · Algorithm 6: Proxy signing

Now Charls signs a sensor reading, and it's the same pattern again. *(Point at sigma.)* Sigma has four parts: John's delegation W-J, a fresh random value, Charls's own certificate secret, and Charls's private key times a hash of the warrant and the message. He sends sigma together with one point, U-C, which bundles all the public parts. One small note: Figure 5 of the paper uses the wrong hash here. The text and the proof use H-two, and so does our code.

### 13 · Algorithm 7: Verification

Anyone can now verify with a single equation. *(Point at the four cards.)* Each term checks one thing: U-C carries the random parts, the CO term checks that both users are certified, John's term checks the warrant, and Charls's term checks the message. If any piece is missing or changed, the equation doesn't balance. Only public keys are needed, and the CO doesn't have to be online.

## Security, results and review (slides 14–24)

### 14 · Security model

The paper considers two strong attackers. The first controls the CO and John and tries to forge a signature for Charls. The second is a malicious proxy that controls the CO and Charls and tries to forge a delegation from John. In both cases the paper uses the forking lemma to argue that a successful forger could be used to solve the discrete log problem.

### 15 · Security properties

From that, the paper claims the standard proxy-signature properties: unforgeability, verifiability, identifiability, prevention of misuse, and undeniability, plus resistance to man-in-the-middle attacks. The descriptions are on the slide.

### 16 · Implementation

We implemented the scheme in Python on the secp256k1 curve. It covers all seven algorithms, plus an end-to-end demo, an automated test suite, and the paper's charts redrawn from its tables.
### 17 · Validation

The honest case verifies, and all five tampering attempts are rejected. The full test suite passes, 16 out of 16. We also timed each operation. The absolute numbers aren't comparable to the paper's, but note that verifying takes about five times as long as signing. That's because the verification equation needs four scalar multiplications, not the two the paper counts.

### 18 · Computational cost

In the paper's cost model, PFCBPS totals 46.69 ms, the lowest of the six schemes and about a quarter of the slowest. Two of the competitors are also pairing-free, so against those the saving comes from doing fewer operations, not from dropping pairings.

### 19 · Communication cost

A delegation or a signature is 65 bytes on the wire, which fits in a single IEEE 802.15.4 radio frame. To be fair, it isn't the smallest: two pairing-based schemes are shorter, but they're much slower.

### 20 · The flaw

While implementing the scheme, we found that it can be forged. *(Point at the two top cards.)* In a normal Schnorr signature, the hash includes the random point R, so changing R changes the hash and you can't work backwards. PFCBPS leaves that point out of two of its hashes, so those values are fixed in advance. *(Point at the dark band.)* That means an attacker can pick the secret number first and then solve for the point that makes the check balance. It works directly on the certificate and delegation checks, and indirectly on the final signature.

### 21 · Attacks 1 & 2

*(Point at the left panel.)* Attack 1 forges a certificate. The attacker picks any t and solves for R, and the certificate check passes without the CO ever being involved. *(Point at the right panel.)* Attack 2 forges a delegation from John, for any warrant, say "sign anything, forever". Pick any W-J, solve for w-J, and Charls's check passes. If Charls then signs with it using the normal algorithm, those signatures verify too. So John's consent is never actually needed, which is exactly what Theorem 3 says can't happen.

### 22 · Attacks 3 & 4

Attack 3 is the most serious. *(Point at the left panel.)* The verifier only sees the combined point U-C, so the signer subtracts the CO and John terms inside U-C, then signs with just their own key. The result verifies under any warrant, with no delegation and not even a certificate. *(Point at the right panel.)* Attack 4 builds on it. If an outsider can get the verifier to use a fake key for Charls, which the paper's own model allows, they run attack 3 with their own key and sign as Charls.

### 23 · Four forgeries

We ran each attack 500 times on our code, after deleting the CO's and John's secrets so nothing could be used by accident. Every run succeeded, each in under a millisecond, and we confirmed them on a second implementation written from the paper's equations. *(Point at "What still holds".)* The basic Schnorr part does hold: nobody can sign for Charls's real key without his private key. The fix is to put the random points into the hashes and send them with the signature.

### 24 · Thank you

Thank you. I'm happy to take questions.
