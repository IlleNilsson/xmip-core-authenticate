//! The few DER moves an alternative signature needs: reading a tag, a
//! length and a value, writing them back, and re-encoding a certificate's
//! `tbsCertificate` without the two parts the alternative signature does not
//! cover (ITU-T X.509 (10/2019) clause 7.2.2): the `signature` field, which
//! names the classical algorithm, and the `altSignatureValue` extension,
//! which is the alternative signature itself. Nothing else is interpreted;
//! every other byte is copied as it lies.

use crate::AuthenticateError;

const SEQUENCE: u8 = 0x30;
const OBJECT_IDENTIFIER: u8 = 0x06;
const VERSION: u8 = 0xA0;
const EXTENSIONS: u8 = 0xA3;

/// `altSignatureValue`, 2.5.29.74, as the OBJECT IDENTIFIER's contents.
const ALT_SIGNATURE_VALUE: &[u8] = &[0x55, 0x1D, 0x4A];

/// One tag, its value, and what follows.
pub(super) fn split(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), AuthenticateError> {
    let (&tag, after_tag) = bytes
        .split_first()
        .ok_or_else(|| AuthenticateError::new("DER ends where a tag should be"))?;
    let (&first, after_first) = after_tag
        .split_first()
        .ok_or_else(|| AuthenticateError::new("DER ends where a length should be"))?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), after_first)
    } else {
        let count = usize::from(first & 0x7F);

        if count == 0 || count > 4 || after_first.len() < count {
            return Err(AuthenticateError::new(
                "DER length is not definite and short",
            ));
        }

        let length = after_first[..count]
            .iter()
            .fold(0usize, |length, &byte| (length << 8) | usize::from(byte));
        (length, &after_first[count..])
    };

    if rest.len() < length {
        return Err(AuthenticateError::new(
            "DER value is shorter than its length says",
        ));
    }

    let (value, following) = rest.split_at(length);
    Ok((tag, value, following))
}

/// A tag and a value, written with the shortest length.
pub(super) fn encode(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![tag];
    let length = value.len();

    if length < 0x80 {
        bytes.push(u8::try_from(length).unwrap_or(0x7F));
    } else {
        let octets = length.to_be_bytes();
        let significant: Vec<u8> = octets
            .iter()
            .copied()
            .skip_while(|&byte| byte == 0)
            .collect();
        bytes.push(0x80 | u8::try_from(significant.len()).unwrap_or(0x7F));
        bytes.extend(significant);
    }

    bytes.extend_from_slice(value);
    bytes
}

/// Every element in a SEQUENCE's contents, in order.
pub(super) fn elements(mut contents: &[u8]) -> Result<Vec<(u8, &[u8])>, AuthenticateError> {
    let mut found = Vec::new();

    while !contents.is_empty() {
        let (tag, value, rest) = split(contents)?;
        found.push((tag, value));
        contents = rest;
    }

    Ok(found)
}

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
