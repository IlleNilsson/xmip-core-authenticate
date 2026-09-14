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
