//! Possession: whether the sender of a certificate holds its key, and signed
//! this arrival with it (ADR-0019, amendment 2026-11-11).
//!
//! A chain proves who it names, never who sent it: anyone who saw a
//! certificate can forward it. Where no handshake bound the chain to the
//! connection, the sender proves it holds the leaf's key with a signature,
//! and that signature must be over this arrival: otherwise any one signature
//! the holder ever made — over an earlier AS2 message, a signed MDN it sent
//! the node — would be replayed beside the public chain and count.
//!
//! So the signature covers a CMS SignerInfo's signed attributes as S/MIME
//! signs them (RFC 5652 section 5.4), and those carry the `messageDigest` of
//! the content (section 11.2). The transport measures the digest of the
//! content it received, and the two must be one. The proofs carry the
//! attributes and the digest, a few hundred bytes, and never the content
//! (`identify::evidence::CERTIFICATE_SIGNED`, `CERTIFICATE_DIGEST`).
//!
//! The leaf's classical key is the one checked. Where a chain must be hybrid
//! (`alt::Hybrid::Required`) its certificates' alternative signatures are
//! verified, and possession is still by the classical key alone.

use asn1::{OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE, expect, read_all};
use identify::Presented;
use identify::evidence::{CERTIFICATE_DIGEST, CERTIFICATE_SIGNATURE, CERTIFICATE_SIGNED};
use webpki::EndEntityCert;

use super::Chain;
use crate::AuthenticateError;

/// `SET` and `SET OF`, constructed: signed attributes as they are signed,
/// and an attribute's values.
const SET: u8 = 0x31;

/// `messageDigest`, 1.2.840.113549.1.9.4 (RFC 5652 section 11.2), as the
/// OBJECT IDENTIFIER's contents.
pub(crate) const MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];

/// Whether the sender of `presented` holds the key of `chain`'s leaf and
/// signed this arrival with it: the `certificate.signature` over the
/// `certificate.signed` attributes, verified with the leaf's public key by
/// every algorithm webpki verifies, and the `messageDigest` those attributes
/// carry the `certificate.digest` the transport measured of this arrival's
/// content.
///
/// # Errors
///
/// A proof missing or not base64, a signature the leaf's key did not make
/// over those attributes, attributes that are not DER or carry no single
/// `messageDigest`, or one that is not this arrival's digest.
pub fn possessed(chain: &Chain, presented: &Presented) -> Result<(), AuthenticateError> {
    let signature = proof(presented, CERTIFICATE_SIGNATURE)?;
    let signed = proof(presented, CERTIFICATE_SIGNED)?;
    let digest = proof(presented, CERTIFICATE_DIGEST)?;
    let leaf = EndEntityCert::try_from(chain.leaf())
        .map_err(|failure| AuthenticateError::new(format!("the leaf is not X.509: {failure}")))?;

    if !webpki::ALL_VERIFICATION_ALGS.iter().any(|algorithm| {
        leaf.verify_signature(*algorithm, &signed, &signature)
            .is_ok()
    }) {
        return Err(AuthenticateError::new(
            "the signature over the signed attributes is not the certificate's key's",
        ));
    }
    if message_digest(&signed)? != digest {
        return Err(AuthenticateError::new(
            "the signature is over another arrival: the messageDigest it signed is not the \
             digest of the content this arrival carried",
        ));
    }
    Ok(())
}

/// The proof `name` decoded from base64.
fn proof(presented: &Presented, name: &str) -> Result<Vec<u8>, AuthenticateError> {
    let encoded = presented.proof(name).ok_or_else(|| {
        AuthenticateError::new(format!(
            "no {name} proof was presented: a certificate that arrived proves nobody until its \
             key signs this arrival"
        ))
    })?;
    codec::base64::decode(encoded.trim())
        .map_err(|_| AuthenticateError::new(format!("the {name} proof is not base64")))
}

/// The one `messageDigest` signed attributes carry.
fn message_digest(signed: &[u8]) -> Result<Vec<u8>, AuthenticateError> {
    let (attributes, after) = expect(signed, SET)?;
    if !after.is_empty() {
        return Err(AuthenticateError::new(
            "something follows the signed attributes",
        ));
    }
    let mut found = None;
    for (tag, attribute) in read_all(attributes)? {
        if tag != SEQUENCE {
            return Err(AuthenticateError::new(
                "a signed attribute is not a SEQUENCE",
            ));
        }
        let (kind, values) = expect(attribute, OBJECT_IDENTIFIER)?;
        if kind != MESSAGE_DIGEST {
            continue;
        }
        let (values, trailing) = expect(values, SET)?;
        if !trailing.is_empty() {
            return Err(AuthenticateError::new(
                "something follows the messageDigest attribute's values",
            ));
        }
        let (digest, more) = expect(values, OCTET_STRING)?;
        if !more.is_empty() || found.replace(digest.to_vec()).is_some() {
            return Err(AuthenticateError::new(
                "the signed attributes carry more than one messageDigest",
            ));
        }
    }
    found.ok_or_else(|| AuthenticateError::new("the signed attributes carry no messageDigest"))
}

#[cfg(test)]
mod tests {
    use super::super::mint::{Authority, content_digest, signed_attributes};
    use super::*;
    use identify::evidence::CERTIFICATE_CHAIN;
    use xcore::mechanism;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    #[test]
    fn only_the_leafs_key_signing_this_arrival_is_possession() {
        let root = Authority::root("Party Root");
        let issued = root.issue("party-x.example", NOW - DAY, NOW + DAY);
        let other = root.issue("party-y.example", NOW - DAY, NOW + DAY);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");
        let arrived = b"ISA*00*          *00*          *ZZ*PARTYX".as_slice();
        let earlier = b"ISA*00*          *00*          *ZZ*EARLIER".as_slice();
        let claim = |signature: &[u8], signed: &[u8], content: &[u8]| {
            Presented::passed(mechanism::certificate(), "CN=party-x.example")
                .with_proof(CERTIFICATE_CHAIN, &issued.pem)
                .with_proof(CERTIFICATE_SIGNATURE, codec::base64::encode(signature))
                .with_proof(CERTIFICATE_SIGNED, codec::base64::encode(signed))
                .with_proof(
                    CERTIFICATE_DIGEST,
                    codec::base64::encode(&content_digest(content)),
                )
        };
        let attributes = signed_attributes(arrived);

        possessed(
            &chain,
            &claim(&issued.sign(&attributes), &attributes, arrived),
        )
        .expect("its own key, over this arrival");

        let forwarded = possessed(
            &chain,
            &claim(&other.sign(&attributes), &attributes, arrived),
        )
        .expect_err("another key signed it");
        assert!(
            forwarded.message.contains("not the certificate's key's"),
            "{forwarded}"
        );

        // Both the signature and what it covers taken from an earlier
        // arrival, beside the public chain: the holder's own signature, and
        // still not over this arrival.
        let before = signed_attributes(earlier);
        let replayed = possessed(&chain, &claim(&issued.sign(&before), &before, arrived))
            .expect_err("replayed");
        assert!(replayed.message.contains("another arrival"), "{replayed}");

        let bare = Presented::passed(mechanism::certificate(), "CN=party-x.example");
        let failure = possessed(&chain, &bare).expect_err("no signature");
        assert!(failure.message.contains(CERTIFICATE_SIGNATURE), "{failure}");
    }

    #[test]
    fn signed_attributes_carry_exactly_one_message_digest() {
        let digest = |contents: &[u8]| {
            asn1::tlv(
                SEQUENCE,
                &[
                    asn1::tlv(OBJECT_IDENTIFIER, MESSAGE_DIGEST),
                    asn1::tlv(SET, &asn1::tlv(OCTET_STRING, contents)),
                ]
                .concat(),
            )
        };
        let one = asn1::tlv(SET, &digest(b"abc"));
        let two = asn1::tlv(SET, &[digest(b"abc"), digest(b"def")].concat());
        let none = asn1::tlv(SET, &[]);

        assert_eq!(message_digest(&one).expect("one"), b"abc");
        assert!(message_digest(&two).is_err(), "two");
        assert!(message_digest(&none).is_err(), "none");
        assert!(
            message_digest(&[one.clone(), one].concat()).is_err(),
            "trailing"
        );
    }
}
