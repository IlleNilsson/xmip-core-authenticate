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
