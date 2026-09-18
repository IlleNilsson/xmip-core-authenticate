//! Certificates minted for tests: a root, an intermediate, a leaf, a CRL.
//!
//! Behind the `mint` feature, which a technology turns on in its
//! dev-dependencies and nothing turns on in a build. The technologies that
//! verify chains each need a chain to verify, and a chain minted here is one
//! they all read the same way (ADR-0044). Every key is fresh per authority,
//! so no test fixture is a secret anyone holds.

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, OtherNameValue,
    RevokedCertParams, SanType, SerialNumber,
};
use time::OffsetDateTime;

#[cfg(feature = "x509-alt")]
use aws_lc_rs::signature::{ML_DSA_65_SIGNING, PqdsaKeyPair};

/// An authority that issues: a root, or an intermediate beneath one.
pub struct Authority {
    certificate: Certificate,
    key: KeyPair,
    /// Whether this is a root: self-signed, held as an anchor, and never
    /// part of what a peer sends.
    root: bool,
    /// The intermediates above this one, nearest first, as PEM; a root has
    /// none. What an issued leaf carries after itself.
    above: Vec<String>,
    /// The ML-DSA key a hybrid authority signs alternative signatures with.
    #[cfg(feature = "x509-alt")]
    alt: Option<PqdsaKeyPair>,
}

/// A certificate an authority issued.
pub struct Issued {
    /// The chain as a transport reports it: the leaf, then the
    /// intermediates, never the root.
    pub pem: String,
    /// The serial, for a CRL to name.
    pub serial: SerialNumber,
}

impl Authority {
    /// A self-signed root named `name`, `O=Partner X`.
    ///
    /// # Panics
    ///
    /// Key generation or signing fails, which a test should hear about.
    #[must_use]
    pub fn root(name: &str) -> Self {
        let key = KeyPair::generate().expect("a key pair");
        let certificate = authority_params(name)
            .self_signed(&key)
            .expect("a self-signed root");

        Self {
            certificate,
            key,
            root: true,
            above: Vec::new(),
            #[cfg(feature = "x509-alt")]
            alt: None,
        }
    }

    /// An intermediate this authority signs.
    ///
    /// # Panics
    ///
    /// Key generation or signing fails.
    #[must_use]
    pub fn intermediate(&self, name: &str) -> Self {
        let key = KeyPair::generate().expect("a key pair");
        let certificate = authority_params(name)
            .signed_by(&key, &self.certificate, &self.key)
            .expect("a signed intermediate");
        // A root above is not part of what a peer sends; an intermediate is.
        let mut above = Vec::new();

        if !self.root {
            above.push(self.certificate.pem());
            above.extend(self.above.iter().cloned());
        }

        Self {
            certificate,
            key,
            root: false,
            above,
            #[cfg(feature = "x509-alt")]
            alt: None,
        }
    }

    /// A leaf for a client, `CN=<common_name>,O=Partner X`, with the common
    /// name as its one DNS name, valid between the two instants in seconds
    /// since the Unix epoch.
    ///
    /// # Panics
    ///
    /// Key generation or signing fails.
    #[must_use]
    pub fn issue(&self, common_name: &str, not_before: i64, not_after: i64) -> Issued {
        let key = KeyPair::generate().expect("a key pair");
        let params = leaf_params(common_name, not_before, not_after);
        let serial = params.serial_number.clone().expect("a serial");
        let certificate = self.sign_leaf(params, &key, self.alt_signer());
        let mut pem = certificate.pem();
        pem.push_str(&self.certificate_pem_if_intermediate());

        for parent in &self.above {
            pem.push_str(parent);
        }

        Issued { pem, serial }
    }

    /// A leaf as [`Authority::issue`] makes it, carrying a user principal
    /// name the way a smart-card certificate does: a subjectAltName otherName
    /// under Microsoft's UPN object identifier (ADR-0054).
    ///
    /// # Panics
    ///
    /// Key generation or signing fails.
    #[must_use]
    pub fn issue_for_user(
        &self,
        common_name: &str,
        principal: &str,
        not_before: i64,
        not_after: i64,
    ) -> Issued {
        let key = KeyPair::generate().expect("a key pair");
        let mut params = leaf_params(common_name, not_before, not_after);
        params.subject_alt_names.push(SanType::OtherName((
            vec![1, 3, 6, 1, 4, 1, 311, 20, 2, 3],
            OtherNameValue::Utf8String(principal.to_string()),
        )));
        let serial = params.serial_number.clone().expect("a serial");
        let certificate = self.sign_leaf(params, &key, self.alt_signer());
        let mut pem = certificate.pem();
        pem.push_str(&self.certificate_pem_if_intermediate());

        for parent in &self.above {
            pem.push_str(parent);
        }

        Issued { pem, serial }
    }

    /// This authority's certificate as PEM: what a node holds as an anchor.
    #[must_use]
    pub fn pem(&self) -> String {
        self.certificate.pem()
    }

    /// A CRL this authority signs, naming the issued certificates given,
    /// dated `now` and good for a day.
    ///
    /// # Panics
    ///
    /// Signing fails.
    #[must_use]
    pub fn crl(&self, revoked: &[&Issued], now: i64) -> String {
        let params = CertificateRevocationListParams {
            this_update: instant(now),
            next_update: instant(now + 86_400),
            crl_number: fresh_serial(),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|issued| RevokedCertParams {
                    serial_number: issued.serial.clone(),
                    revocation_time: instant(now - 1),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };

        params
            .signed_by(&self.certificate, &self.key)
            .expect("a signed list")
            .pem()
            .expect("PEM")
    }

    /// An intermediate rides in the chain a leaf sends; a root does not.
    fn certificate_pem_if_intermediate(&self) -> String {
        if self.root {
            String::new()
        } else {
            self.certificate.pem()
        }
    }
}

impl Authority {
    /// The leaf signed by this authority, classically, and with an
    /// alternative signature where an alternative signer is given.
    fn sign_leaf(
        &self,
        params: CertificateParams,
        key: &KeyPair,
        alt_signer: Option<&Self>,
    ) -> Certificate {
        let classical = |params: CertificateParams, key: &KeyPair| {
            params
                .signed_by(key, &self.certificate, &self.key)
                .expect("a signed leaf")
        };

        match alt_signer {
            #[cfg(feature = "x509-alt")]
            Some(signer) => {
                let alt = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).expect("an ML-DSA key");
                let by = signer.alt.as_ref().expect("a hybrid signer");
                hybrid::sign(params, key, &alt, by, &classical)
            }
            _ => classical(params, key),
        }
    }

    /// This authority, where it is hybrid: what alternative-signs what it
    /// issues.
    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn alt_signer(&self) -> Option<&Self> {
        #[cfg(feature = "x509-alt")]
        {
            self.alt.as_ref().map(|_| self)
        }
        #[cfg(not(feature = "x509-alt"))]
        {
            None
        }
    }
}

#[cfg(feature = "x509-alt")]
impl Authority {
    /// A hybrid root: self-signed classically and alternative-signed by its
    /// own ML-DSA-65 key, which it carries in `subjectAltPublicKeyInfo`.
    ///
    /// # Panics
    ///
    /// Key generation or signing fails.
    #[must_use]
    pub fn hybrid_root(name: &str) -> Self {
        let key = KeyPair::generate().expect("a key pair");
        let alt = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).expect("an ML-DSA key");
        let certificate = hybrid::sign(authority_params(name), &key, &alt, &alt, &|params, key| {
            params.self_signed(key).expect("a self-signed root")
        });

        Self {
            certificate,
            key,
            root: true,
            above: Vec::new(),
            alt: Some(alt),
        }
    }

    /// A hybrid intermediate this hybrid authority signs both ways.
    ///
    /// # Panics
    ///
    /// This authority is not hybrid, or key generation or signing fails.
    #[must_use]
    pub fn hybrid_intermediate(&self, name: &str) -> Self {
        let key = KeyPair::generate().expect("a key pair");
        let alt = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).expect("an ML-DSA key");
        let signer = self.alt.as_ref().expect("a hybrid authority");
        let certificate = hybrid::sign(
            authority_params(name),
            &key,
            &alt,
            signer,
            &|params, key| {
                params
                    .signed_by(key, &self.certificate, &self.key)
                    .expect("a signed intermediate")
            },
        );
        let mut above = Vec::new();

        if !self.root {
            above.push(self.certificate.pem());
            above.extend(self.above.iter().cloned());
        }

        Self {
            certificate,
            key,
            root: false,
            above,
            alt: Some(alt),
        }
    }

    /// A leaf this authority signs classically whose alternative signature
    /// is another hybrid authority's: a forgery, for a test to refuse.
    ///
    /// # Panics
    ///
    /// The other authority is not hybrid, or key generation or signing fails.
    #[must_use]
    pub fn issue_alt_signed_by(
        &self,
        alt_signer: &Self,
        common_name: &str,
        not_before: i64,
        not_after: i64,
    ) -> Issued {
        let key = KeyPair::generate().expect("a key pair");
        let params = leaf_params(common_name, not_before, not_after);
        let serial = params.serial_number.clone().expect("a serial");
        let certificate = self.sign_leaf(params, &key, Some(alt_signer));
        let mut pem = certificate.pem();
        pem.push_str(&self.certificate_pem_if_intermediate());

        for parent in &self.above {
            pem.push_str(parent);
        }

        Issued { pem, serial }
    }
}

#[cfg(feature = "x509-alt")]
mod hybrid;

fn authority_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.distinguished_name.push(DnType::CommonName, name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Partner X");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(fresh_serial());
    params
}

fn leaf_params(common_name: &str, not_before: i64, not_after: i64) -> CertificateParams {
    let mut params = CertificateParams::new(vec![common_name.to_string()]).expect("params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Partner X");
    params.not_before = instant(not_before);
    params.not_after = instant(not_after);
    params.serial_number = Some(fresh_serial());
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params
}

fn instant(seconds: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(seconds).expect("an instant")
}

/// A serial no two certificates share within a process.
fn fresh_serial() -> SerialNumber {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);
    let number = NEXT.fetch_add(1, Ordering::Relaxed);

    SerialNumber::from_slice(&number.to_be_bytes())
}
