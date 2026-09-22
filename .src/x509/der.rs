//! The DER move an alternative signature needs: re-encoding a certificate's
//! `tbsCertificate` without the two parts the alternative signature does not
//! cover (ITU-T X.509 (10/2019) clause 7.2.2): the `signature` field, which
//! names the classical algorithm, and the `altSignatureValue` extension,
//! which is the alternative signature itself. Nothing else is interpreted;
//! every other byte is copied as it lies. Reading and writing an element is
//! the estate's one X.690 reader, `xmip-core-asn1`, which this file carried a
//! copy of until 2026-09-22.

use crate::AuthenticateError;
use asn1::{read as split, read_all as elements, tlv as encode};

const SEQUENCE: u8 = 0x30;
const OBJECT_IDENTIFIER: u8 = 0x06;
const VERSION: u8 = 0xA0;
const EXTENSIONS: u8 = 0xA3;

/// `altSignatureValue`, 2.5.29.74, as the OBJECT IDENTIFIER's contents.
const ALT_SIGNATURE_VALUE: &[u8] = &[0x55, 0x1D, 0x4A];

/// The certificate's `tbsCertificate` re-encoded without its `signature`
/// field and without the `altSignatureValue` extension: what the alternative
/// signature was computed over.
///
/// # Errors
///
/// The bytes are not a DER certificate.
pub(super) fn pre_tbs(certificate: &[u8]) -> Result<Vec<u8>, AuthenticateError> {
    let (SEQUENCE, body, _) = split(certificate)? else {
        return Err(AuthenticateError::new("a certificate is a SEQUENCE"));
    };
    let (SEQUENCE, tbs, _) = split(body)? else {
        return Err(AuthenticateError::new("tbsCertificate is a SEQUENCE"));
    };
    let fields = elements(tbs)?;
    let signature_at = usize::from(fields.first().is_some_and(|(tag, _)| *tag == VERSION)) + 1;
    let mut contents = Vec::with_capacity(tbs.len());

    for (index, (tag, value)) in fields.iter().enumerate() {
        if index == signature_at {
            continue;
        }

        if *tag == EXTENSIONS {
            contents.extend(encode(EXTENSIONS, &without_alt_signature_value(value)?));
        } else {
            contents.extend(encode(*tag, value));
        }
    }

    Ok(encode(SEQUENCE, &contents))
}

/// The `[3] Extensions` value with the `altSignatureValue` extension dropped.
fn without_alt_signature_value(explicit: &[u8]) -> Result<Vec<u8>, AuthenticateError> {
    let (SEQUENCE, list, _) = split(explicit)? else {
        return Err(AuthenticateError::new("extensions are a SEQUENCE"));
    };
    let mut kept = Vec::with_capacity(list.len());

    for (tag, extension) in elements(list)? {
        let (OBJECT_IDENTIFIER, oid, _) = split(extension)? else {
            return Err(AuthenticateError::new("an extension starts with its OID"));
        };

        if oid != ALT_SIGNATURE_VALUE {
            kept.extend(encode(tag, extension));
        }
    }

    Ok(encode(SEQUENCE, &kept))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_length_round_trips_in_both_forms() {
        let short = encode(0x04, &[1, 2, 3]);
        assert_eq!(short, vec![0x04, 0x03, 1, 2, 3]);

        let long = encode(0x04, &[7; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2C]);
        let (tag, value, rest) = split(&long).expect("read");
        assert_eq!((tag, value.len(), rest.len()), (0x04, 300, 0));
    }

    #[test]
    fn the_pre_tbs_drops_the_signature_field_and_the_alt_signature_value() {
        // A tiny certificate shape: version, serial, signature, one extension
        // that is altSignatureValue and one that is not.
        let alt = encode(
            SEQUENCE,
            &[encode(0x06, ALT_SIGNATURE_VALUE), encode(0x04, &[9])].concat(),
        );
        let other = encode(
            SEQUENCE,
            &[encode(0x06, &[0x55, 0x1D, 0x0F]), encode(0x04, &[1])].concat(),
        );
        let extensions = encode(
            EXTENSIONS,
            &encode(SEQUENCE, &[other.clone(), alt].concat()),
        );
        let tbs = [
            encode(VERSION, &encode(0x02, &[2])),
            encode(0x02, &[1]),
            encode(SEQUENCE, &encode(0x06, &[0x2A, 0x03])),
            extensions,
        ]
        .concat();
        let certificate = encode(SEQUENCE, &encode(SEQUENCE, &tbs));

        let pre = pre_tbs(&certificate).expect("pre-TBS");
        let (_, contents, _) = split(&pre).expect("a SEQUENCE");
        let fields = elements(contents).expect("fields");

        assert_eq!(fields.len(), 3, "version, serial, extensions");
        assert_eq!(fields[2].0, EXTENSIONS);
        let (_, list, _) = split(fields[2].1).expect("extensions");
        assert_eq!(list, other.as_slice());
    }
}
