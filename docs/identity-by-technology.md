# Identity and security by technology

Where identity actually lives, per technology, against the standards that
define it.

ADR-0019 fixes the rule this document is sorted by:

> Anything Xmip can read before Message creation is **transport** identity.
> Anything that requires the Message to exist is **message** identity.

Both may be present, either may be absent, and neither substitutes for the
other. This catalogue exists so that a Receive Location's security
configuration is a lookup rather than an argument.

Every technology named here appears in `architecture.toml`. Where a row says
*none*, that is a property of the standard and cannot be configured away — the
identity has to come from the other layer or from the circumstance.

---

## 1. Transport layer

### File and file-like

| Technology | Channel | Credential | Standard |
| --- | --- | --- | --- |
| `file` | none | none | implied: path, filesystem ACL, owning account |
| `ftp` | none | USER/PASS, cleartext | RFC 959 |
| `ftp` (FTPS) | TLS | password, or X.509 client certificate | RFC 4217 |
| `sftp` | SSH-2 transport | public key, password, keyboard-interactive, GSSAPI | RFC 4251–4254, RFC 4252 |
| `webdav` | TLS | HTTP authentication, inherited | RFC 4918 |
| `smb` | SMB3 encryption and signing | NTLM, Kerberos | MS-SMB2 |
| `nfs` | RPCSEC_GSS | AUTH_SYS (trusted uid), Kerberos v5 | RFC 7530 (v4.0), RFC 8881 (v4.1), RFC 2203 |

`file` is the case that proves implied identity is still identity: nothing is
presented, and the path, the permissions and the account that could write there
are the evidence.

### HTTP family

| Technology | Channel | Credential | Standard |
| --- | --- | --- | --- |
| `http` | none | `Authorization` header, source address, or nothing | RFC 9110 §11, RFC 7235 |
| `http` over TLS | TLS, optional client certificate | as above, plus the certificate | RFC 8446 |
| `websocket` | TLS when `wss` | the opening handshake is HTTP, so HTTP auth applies | RFC 6455 |

Scheme by scheme, the credential mechanisms are unchanged; only the channel
differs. The mechanisms themselves:

| Mechanism | Standard | Xmip module |
| --- | --- | --- |
| Basic | RFC 7617 | `xmip-core-authenticate-basic` |
| Digest | RFC 7616 | `xmip-core-authenticate-digest` |
| Bearer | RFC 6750 | `xmip-core-authenticate-bearer` |
| Negotiate / SPNEGO | RFC 4559 | `xmip-core-authenticate-kerberos` |
| Mutual TLS | RFC 8446, RFC 8705 for token binding | `xmip-core-authenticate-mutual-tls` |
| OAuth 2.0 | RFC 6749 | `xmip-core-authenticate-oauth2` |
| OpenID Connect | OIDC Core 1.0 | `xmip-core-authenticate-oidc` |
| API key | no standard — vendor convention | `xmip-core-authenticate-api-key` |

API key is deliberately last. It is the only one in the list with no
specification behind it, and it should be treated as a shared secret in a
header rather than as authentication.

### Mail

| Technology | Channel | Credential | Standard |
| --- | --- | --- | --- |
| `smtp` | STARTTLS or implicit TLS | SASL via `AUTH` | RFC 5321, RFC 3207, RFC 4954 |
| `imap` | STARTTLS or implicit TLS | SASL via `AUTHENTICATE` | RFC 9051, RFC 4959 |
| `pop3` | STARTTLS or implicit TLS | SASL, `USER`/`PASS`, APOP | RFC 1939, RFC 5034 |

Mail is the clearest everyday example of the two layers being wholly
independent: the submitting account and the claimed author are different facts,
which is the entire reason SPF, DKIM and DMARC exist at the message layer:

| Mechanism | Proves | Standard |
| --- | --- | --- |
| SPF | the sending host is authorised for the envelope domain | RFC 7208 |
| DKIM | the message was signed by the claimed domain and is unaltered | RFC 6376 |
| DMARC | alignment between the two, plus policy and reporting | **RFC 9989**, which obsoleted RFC 7489 and RFC 9091 in May 2026 |

DMARC is worth the emphasis: it moved to Standards Track in 2026, and anything
citing RFC 7489 is now citing an obsoleted Informational document.

### Messaging and streaming

| Technology | Channel | Credential | Standard |
| --- | --- | --- | --- |
| `amqp` | TLS | SASL layer, part of the protocol | OASIS AMQP 1.0 |
| `rabbitmq` | TLS | SASL `PLAIN`, `EXTERNAL` for client certificates | AMQP 0-9-1 |
| `mqtt` | TLS | CONNECT username and password, client certificate; MQTT 5 adds enhanced authentication | OASIS MQTT 3.1.1 / 5.0 |
| `kafka` | TLS, mTLS | SASL `PLAIN`, `SCRAM-SHA-256/512`, `GSSAPI`, `OAUTHBEARER` | RFC 5802, RFC 7628 |
| `nats` | TLS | NKEY, signed user JWT, token, user and password | NATS protocol |
| `activemq` | TLS | JAAS realms, SASL | OpenWire, AMQP, STOMP |
| `ibm-mq` | TLS | CHLAUTH channel rules, CONNAUTH to LDAP or the operating system | IBM MQ |
| `msmq` | Windows integrated | Windows account, queue ACL | MS-MQMQ |
| `redis-streams` | TLS | AUTH, ACL users | RESP3 |

MQTT 5's enhanced authentication and Kafka's `OAUTHBEARER` are both the same
move: a messaging protocol admitting that a username and password is not enough
and borrowing SASL and OAuth rather than inventing a scheme.

### Cloud

| Technology | Channel | Credential | Standard |
| --- | --- | --- | --- |
| `s3`, `aws-sqs`, `aws-sns`, `aws-kinesis` | TLS | Signature Version 4, IAM role, STS session | AWS SigV4 |
| `azure-blob`, `azure-service-bus`, `azure-event-hubs`, `azure-event-grid` | TLS | Shared Key, SAS token, Entra ID OAuth 2.0 | Azure |
| `google-cloud-storage`, `google-pub-sub` | TLS | OAuth 2.0 service account, workload identity, HMAC | Google Cloud |

All three are request signing rather than session authentication. The identity
is proven per request, which means there is no connection identity to inherit —
a distinction that matters when a Journey spans several calls.

### Database

| Technology | Channel | Credential | Standard |
| --- | --- | --- | --- |
| `mssql` | TDS encryption | Windows integrated, Kerberos, SQL login, Entra ID | MS-TDS |
| `postgresql` | TLS | SCRAM-SHA-256, GSSAPI, certificate, LDAP | RFC 5802 |
| `mysql` | TLS | `caching_sha2_password`, certificate, PAM | MySQL protocol |
| `oracle` | Native encryption, TLS | operating system, Kerberos, wallet | Oracle Net |
| `sqlite` | none — it is a file | none | filesystem permissions |

`sqlite` belongs with `file`. There is no channel and no credential because
there is no connection; the identity is whoever could open the file.

### Industrial, embedded and low-level

| Technology | Channel | Credential | Standard |
| --- | --- | --- | --- |
| `opc-ua` | SecurityPolicy, X.509 application instance certificate | anonymous, username, X.509, issued token | IEC 62541 |
| `modbus` | none in the base protocol | none | Modbus Application Protocol |
| `modbus` secure | TLS | X.509 with role extension | Modbus/TCP Security |
| `can-bus` | none | none; SecOC adds message authentication codes | ISO 11898, AUTOSAR SecOC |
| `serial` | none | none | implied: physical access |
| `tcp`, `udp` | none | none | RFC 9293 (obsoletes 793), RFC 768 |
| `unix-socket` | none | peer credentials from the kernel | `SO_PEERCRED` |
| `named-pipe` | none | Windows impersonation, caller SID | MS-RPC |
| `mllp` | none | none | HL7 MLLP |

This block is why transport authentication cannot be assumed. OPC UA is the
outlier that did it properly — a certificate for the *application* and a
separate token for the *user*, which is the two-layer model built into a single
industrial protocol. Modbus and CAN bus have nothing, by design and by age, and
`unix-socket` and `named-pipe` carry a kernel-vouched identity that is stronger
than most credentials and is never presented at all.

MLLP deserves its own note: it is a framing protocol with no security whatever,
carrying healthcare data. All of its identity is at the message layer, in MSH.

---

## 2. Message layer

Identity inside the payload, after Message creation.

| Representation | Identity carried | Standard |
| --- | --- | --- |
| `edi-edifact` | UNB S002 sender identification and qualifier, S003 recipient, S005 recipient reference or password | ISO 9735 |
| `edi-edifact` signed | AUTACK, integrity and authentication segments | ISO 9735-5/6/7 |
| `edi-x12` | ISA05–ISA08 sender and receiver qualifier and id, ISA01–ISA04 authorization and security information | ASC X12.5 |
| `hl7-er7` | MSH-3 sending application, MSH-4 sending facility, MSH-8 security | HL7 v2.x |
| `xml` | XML Signature, XML Encryption | W3C XMLDSIG, RFC 3275 |
| `json` | JWS, JWE, JWT, JWK | RFC 7515, 7516, 7519, 7517 |
| `multipart` | S/MIME 4.0, PGP/MIME | RFC 8551, RFC 3156 |
| `avro`, `protobuf`, `binary` | none native — identity belongs to the envelope or a wrapper | — |
| `csv`, `fixed-width`, `text`, `toml`, `yaml`, `form-urlencoded` | none | — |

The EDI rows are the important ones. **X12's ISA and EDIFACT's UNB carry
identity but no cryptography** — they are claims, not proof, and treating them
as authentication is the classic B2B mistake. They name the counterparty so a
Journey can be routed and billed; proving it is the transport's job, or AS2's.

For contracts, `fhir` is the one that carries identity semantics of its own:
Provenance and Signature resources, and SMART on FHIR scopes layered on OAuth
2.0. The rest — `json-schema`, `xml-schema`, `openapi`, `wsdl`, `avro`,
`protobuf` — describe structure and say nothing about who sent it.

---

## 3. Logic layer

`xmip-core-logic-*` sits between the two, and SOAP is where the industry put
message-layer security first.

| Technology | Security | Standard |
| --- | --- | --- |
| `soap` | WS-Security: UsernameToken, X.509 Token Profile, SAML Token Profile; WS-Trust, WS-SecureConversation, WS-SecurityPolicy | OASIS WSS 1.1 |
| `grpc` | TLS and mTLS for the channel, per-call credentials in metadata, usually an OAuth 2.0 bearer or JWT | gRPC |
| `http-api` | OAuth 2.0, OIDC, API keys, HTTP Message Signatures | RFC 6749, RFC 9421 |

RFC 9421 is worth attention. It signs selected HTTP headers *and* the body,
which places it deliberately across the line this document draws — it is read
before Message creation, so Xmip treats it as transport identity, but what it
proves is integrity of the content.

---

## 4. What the sort added to the estate

Sorting the catalogue against the standards exposed a gap, now closed:
`architecture.toml` gained `xmip-core-transport-as2` and
`xmip-core-transport-as4` at architectureVersion 0.15.0, taking the estate from
292 repositories to 294.

**AS2** — RFC 4130 — the second
EDIINT applicability statement, after AS1 over SMTP in RFC 3335. Structured
business data, X12 or EDIFACT or XML, packaged in MIME, authenticated and
encrypted with Cryptographic Message Syntax in S/MIME body parts, and
acknowledged by a `multipart/signed` Message Disposition Notification. It is the
dominant standard for internet EDI — retail, Drummond certification — and
BizTalk ships it as a first-class adapter.

It is also the single cleanest example of this document's whole argument: HTTPS
for the channel, S/MIME for the sender, X12 or EDIFACT identifiers for the
counterparty, and a signed MDN proving receipt. Four facts, four layers, none
redundant.

The IETF EDIINT working group has `draft-ietf-ediint-rfc4130bis` in progress to
modernise it, so an implementation should track that rather than freeze on the
2005 text.

**AS4** (OASIS ebMS 3.0 AS4 profile) is the same argument in European public
procurement and energy, and is equally absent.

Both are transports in the Xmip sense, and both are declared with explicit
technology-to-technology dependencies — the case `repository-model.md`
section 4 requires to be declared rather than inferred:

```toml
[xmip.core.transport.as2]
dependency = ["xmip-core-transport-http", "xmip-core-message-multipart",
              "xmip-core-authenticate-certificate"]

[xmip.core.transport.as4]
dependency = ["xmip-core-transport-http", "xmip-core-logic-soap",
              "xmip-core-authenticate-certificate"]
```

A transport that depends on the message layer looks like a layering violation
and is not one. AS2's signing *is* S/MIME over MIME parts, and AS4's *is*
WS-Security over SOAP. The dependency is real, so it is declared.

## 5. Alignment

Where a technology carries identity on both layers, the two may disagree, and
ADR-0019 clause 7 rules that this is configured alignment rather than
precedence — DMARC's structure, applied to the estate. AS2 is the case that
needs it: the transport certificate names the VAN, `ISA06` names the
counterparty, and both are true.

```toml
[receive.location.partner-x.identity]
alignment      = "none"      # none | relaxed | strict
onMisalignment = "accept"    # accept | quarantine | reject
```

The default is `none`, because the technologies in this catalogue that carry
two identities are overwhelmingly the relaying ones.

---

## 6. Implementation specifications

Identity is one thing a transport specification governs. The specification a
Module implements against is another, and it belongs beside it:

| Module | Implements against |
| --- | --- |
| `xmip-core-transport-file` | Platform file-system behaviour and the Rust file-system APIs |
| `xmip-core-transport-tcp` | IETF RFC 9293 |
| `xmip-core-transport-http` | IETF RFC 9110, with the applicable HTTP/1.1, HTTP/2 and HTTP/3 specifications. Depends on `xmip-core-transport-tcp` |
| `xmip-core-transport-websocket` | IETF RFC 6455 and applicable extensions. Depends on `xmip-core-transport-http` |
| `xmip-core-transport-mllp` | MLLP framing over TCP. Depends on `xmip-core-transport-tcp` |
| `xmip-core-contract-json-schema` | JSON Schema specifications and vocabularies |
| `xmip-core-contract-xml-schema` | W3C XML Schema specifications |

Representation and Path collaborators stay separate repositories:
`xmip-core-message-json` with `xmip-core-path-json-pointer`,
`xmip-core-message-xml` with `xmip-core-path-xpath`. Logic sits apart again:
`xmip-core-logic-http-api`, `xmip-core-logic-soap`, `xmip-core-logic-grpc`.
SOAP may use HTTP, XML and WSDL without becoming any of them; gRPC may use
HTTP and Protocol Buffers while keeping its own operation semantics.

> **Protocol compliance is claimed only after conformance evidence exists.**
> Implementing against a specification and conforming to it are different
> statements, and only the second is a promise.

---

## Provenance

RFC numbers were verified against `rfc-editor.org` and the IETF Datatracker on
2026-08-25, not quoted from memory. Two were wrong before checking, and both
would have aged badly:

- **DMARC** is RFC 9989, not RFC 7489. The replacement was published in May 2026
  and moved DMARC to Standards Track.
- **TCP** is RFC 9293, not RFC 793. RFC 9293 collected 793 and its seven
  updating RFCs into one specification in 2022.

Where a technology is governed by ISO, OASIS, IEC, HL7 or ASC X12 rather than
the IETF, the body is named instead of an RFC. Those were not independently
verified and are the rows most worth a second look: `edi-edifact` (ISO 9735),
`edi-x12` (ASC X12.5), `opc-ua` (IEC 62541), and the OASIS families for AMQP,
MQTT and WS-Security.
