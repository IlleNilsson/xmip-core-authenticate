//! What a minted leaf's holder signs to prove it holds the key: an
//! arrival's signed attributes, as S/MIME signs them, carrying the digest
//! of its content (`x509::possessed`; ADR-0019, amendment 2026-11-11).

use asn1::{OBJECT_IDENTIFIER, OCTET_STRING, SEQUENCE, tlv};
use identify::Presented;
use identify::evidence::{CERTIFICATE_DIGEST, CERTIFICATE_SIGNATURE, CERTIFICATE_SIGNED};
use sha2::{Digest, Sha256};

use super::Issued;
use crate::x509::possession::MESSAGE_DIGEST;

/// `SET OF`, constructed.
const SET: u8 = 0x31;

/// `contentType`, 1.2.840.113549.1.9.3, and `id-data`, 1.2.840.113549.1.7.1
/// (RFC 5652 section 11.1), as their OBJECT IDENTIFIERs' contents.
const CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
const DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];

/// The digest a transport measures of `content`: SHA-256.
#[must_use]
pub fn content_digest(content: &[u8]) -> Vec<u8> {
    Sha256::digest(content).to_vec()
}

/// The signed attributes a signer of `content` signs, as they are signed: a
/// DER `SET` of its content type, data, and its `messageDigest`.
#[must_use]
pub fn signed_attributes(content: &[u8]) -> Vec<u8> {
    let attribute = |kind: &[u8], value: Vec<u8>| {
        tlv(
            SEQUENCE,
            &[tlv(OBJECT_IDENTIFIER, kind), tlv(SET, &value)].concat(),
        )
    };
    tlv(
        SET,
        &[
            attribute(CONTENT_TYPE, tlv(OBJECT_IDENTIFIER, DATA)),
            attribute(MESSAGE_DIGEST, tlv(OCTET_STRING, &content_digest(content))),
        ]
        .concat(),
    )
}

impl Issued {
    /// `data` signed with the leaf's key, as its holder signs: ECDSA P-256
    /// with SHA-256, the signature in DER.
    ///
    /// # Panics
    /// Signing fails.
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        rcgen::SigningKey::sign(&self.key, data).expect("a signature")
    }

    /// `claim` with the proof its holder gives for an arrival carrying
    /// `content`: the signed attributes of `content` signed with the leaf's
    /// key, and the digest the transport measured of it, each base64.
    #[must_use]
    pub fn possessing(&self, claim: Presented, content: &[u8]) -> Presented {
        let attributes = signed_attributes(content);
        claim
            .with_proof(
                CERTIFICATE_SIGNATURE,
                codec::base64::encode(&self.sign(&attributes)),
            )
            .with_proof(CERTIFICATE_SIGNED, codec::base64::encode(&attributes))
            .with_proof(
                CERTIFICATE_DIGEST,
                codec::base64::encode(&content_digest(content)),
            )
    }
}
