//! The DER move an alternative signature needs: re-encoding a certificate's
//! `tbsCertificate` without the two parts the alternative signature does not
//! cover (ITU-T X.509 (10/2019) clause 7.2.2): the `signature` field, which
//! names the classical algorithm, and the `altSignatureValue` extension,
//! which is the alternative signature itself. Nothing else is interpreted;
//! every other byte is copied as it lies. Reading and writing an element is
//! the estate's one X.690 reader, `xmip-core-library-asn1`, which this file carried a
//! copy of until 2026-09-22.

use crate::AuthenticateError;
use asn1::{OBJECT_IDENTIFIER, SEQUENCE, context, read, read_all, tlv};

/// `[0] EXPLICIT Version`.
const VERSION: u8 = context(0, true);
/// `[3] EXPLICIT Extensions`.
const EXTENSIONS: u8 = context(3, true);

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
    let (SEQUENCE, body, _) = read(certificate)? else {
        return Err(AuthenticateError::new("a certificate is a SEQUENCE"));
    };
    let (SEQUENCE, tbs, _) = read(body)? else {
        return Err(AuthenticateError::new("tbsCertificate is a SEQUENCE"));
    };
    let fields = read_all(tbs)?;
    let signature_at = usize::from(fields.first().is_some_and(|(tag, _)| *tag == VERSION)) + 1;
    let mut contents = Vec::with_capacity(tbs.len());

    for (index, (tag, value)) in fields.iter().enumerate() {
        if index == signature_at {
            continue;
        }

        if *tag == EXTENSIONS {
            contents.extend(tlv(EXTENSIONS, &without_alt_signature_value(value)?));
        } else {
            contents.extend(tlv(*tag, value));
        }
    }

    Ok(tlv(SEQUENCE, &contents))
}

/// The `[3] Extensions` value with the `altSignatureValue` extension dropped.
fn without_alt_signature_value(explicit: &[u8]) -> Result<Vec<u8>, AuthenticateError> {
    let (SEQUENCE, list, _) = read(explicit)? else {
        return Err(AuthenticateError::new("extensions are a SEQUENCE"));
    };
    let mut kept = Vec::with_capacity(list.len());

    for (tag, extension) in read_all(list)? {
        let (OBJECT_IDENTIFIER, oid, _) = read(extension)? else {
            return Err(AuthenticateError::new("an extension starts with its OID"));
        };

        if oid != ALT_SIGNATURE_VALUE {
            kept.extend(tlv(tag, extension));
        }
    }

    Ok(tlv(SEQUENCE, &kept))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_length_round_trips_in_both_forms() {
        let short = tlv(0x04, &[1, 2, 3]);
        assert_eq!(short, vec![0x04, 0x03, 1, 2, 3]);

        let long = tlv(0x04, &[7; 300]);
        assert_eq!(&long[..4], &[0x04, 0x82, 0x01, 0x2C]);
        let (tag, value, rest) = read(&long).expect("read");
        assert_eq!((tag, value.len(), rest.len()), (0x04, 300, 0));
    }

    #[test]
    fn the_pre_tbs_drops_the_signature_field_and_the_alt_signature_value() {
        // A tiny certificate shape: version, serial, signature, one extension
        // that is altSignatureValue and one that is not.
        let alt = tlv(
            SEQUENCE,
            &[tlv(0x06, ALT_SIGNATURE_VALUE), tlv(0x04, &[9])].concat(),
        );
        let other = tlv(
            SEQUENCE,
            &[tlv(0x06, &[0x55, 0x1D, 0x0F]), tlv(0x04, &[1])].concat(),
        );
        let extensions = tlv(EXTENSIONS, &tlv(SEQUENCE, &[other.clone(), alt].concat()));
        let tbs = [
            tlv(VERSION, &tlv(0x02, &[2])),
            tlv(0x02, &[1]),
            tlv(SEQUENCE, &tlv(0x06, &[0x2A, 0x03])),
            extensions,
        ]
        .concat();
        let certificate = tlv(SEQUENCE, &tlv(SEQUENCE, &tbs));

        let pre = pre_tbs(&certificate).expect("pre-TBS");
        let (_, contents, _) = read(&pre).expect("a SEQUENCE");
        let fields = read_all(contents).expect("fields");

        assert_eq!(fields.len(), 3, "version, serial, extensions");
        assert_eq!(fields[2].0, EXTENSIONS);
        let (_, list, _) = read(fields[2].1).expect("extensions");
        assert_eq!(list, other.as_slice());
    }
}
