# xmip-core-authenticate

The middle gate: is the claim true. Handed the claim `xmip-core-identify` read
out of the arrival and what the Receive Location declared it would take, it
verifies the presented credential and resolves it to a Party, or refuses.

The Party is the output, never the input. Anonymous is an authenticated
outcome, not a skipped gate. Authentication happens once, where the credential
arrives; whether the Party may do what it is about to do is authorization's
question, asked every time.

ADR-0019 governs identity in both directions and ADR-0050 makes each
technology under this repository one mechanism at this gate; identity per
technology, against the standards, is `doc/identity-by-technology.md` beside
this file. `architecture.toml` names the technologies.

## The clock

`authenticate::clock` is the one time every verifier reads and the one window
it holds a credential to: `[not_before, not_on_or_after)`, as RFC 7519 and
SAML Core say, widened by a leeway at both ends. Ten technologies carried
their own `now()` and their own reading of the bound until 2026-09-24.

## The stores

`authenticate::store` is the credential store the password-shaped verifiers
share — `password`, `basic`, `digest` and `scram` — holding a SCRAM-SHA-256
verifier and never the password. `authenticate::secret` is the hashed secret
store with expiry `api-key` and `bearer` verify against: a secret the node
minted with full entropy, kept as its SHA-256 under the name it was issued
to. Until 2026-09-24 `api-key` and `bearer` each carried the second.

## The claim is identify's

A verifier is handed `identify::Presented`, and names it from `identify`:
this crate re-exports nothing of the first gate's (the owner, 2026-09-24).

## JOSE keys, behind a feature

`jwt` and `oidc` verify a JWS with the same keys. The `jose` feature turns on
`authenticate::jose`: HS256, RS256 and ES256 keys, a key set read from a JSON
Web Key Set document, and one rule for choosing a key — the one the token
names, which must serve its algorithm, or every key of the algorithm where it
names none.

## X.509, behind a feature

What `certificate` and `mutual-tls` both need lives here (ADR-0044) and off
by default: the `x509` feature turns on `authenticate::x509` — a chain read
from PEM, walked to a held anchor by webpki over ring, its validity and its
CRLs checked offline (ADR-0045), and a `Name` that compares distinguished
names by their attributes in any order. The sixteen technologies that never
see a certificate carry none of it. The `mint` feature, for tests only,
issues roots, intermediates, leaves and CRLs with fresh keys so that every
verifier tests against a chain minted the same way; it ships in no build.
The crate tests its own module through a dev-dependency on itself with
`mint` on, which is how Cargo turns a feature on for the tests alone.

`x509-alt` adds the alternative, post-quantum signature a hybrid certificate
carries (ITU-T X.509 (10/2019) clause 9.8): ML-DSA in its three parameter
sets, verified by aws-lc-rs along the very path the classical walk proved,
under a policy of ignored, where present or required. Its own feature
because ring has none, so a package is quantum-ready or not (ADR-0033,
amendment 2026-09-18). Composite signatures are the next slice.
