use openssl::asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{extension, X509Builder, X509Extension, X509Name, X509NameBuilder, X509};

/// A cryptographic key used for signing certificates
///
/// Because this crate is only used for generating test certificates,
/// this key is also used when only a public key is strictly required.
#[derive(Clone)]
pub struct PrivateKey(OpensslKey);

// ## Dangerous!
// impl std::fmt::Debug for PrivateKey {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         let key_priv = self.as_openssl_pkey();
//         let key_pub = key_priv.public_key_to_pem().unwrap();
//         let key_pub = std::str::from_utf8(&key_pub).unwrap();
//         f.debug_tuple("PrivateKey").field(&key_pub).finish()
//     }
// }

#[derive(Clone)]
enum OpensslKey {
    Rsa(PKey<Private>),
}

impl PrivateKey {
    /// Create a new random 2048-bit RSA private key.
    ///
    pub fn new_rsa() -> PrivateKey {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        PrivateKey(OpensslKey::Rsa(pkey))
    }

    /// Output the key in PEM PKCS8 format.
    pub fn to_pem(&self) -> Vec<u8> {
        match &self.0 {
            OpensslKey::Rsa(k) => k.private_key_to_pem_pkcs8().unwrap(),
        }
    }

    /// Output the key in DER format.
    pub fn to_der(&self) -> Vec<u8> {
        match &self.0 {
            OpensslKey::Rsa(k) => k.private_key_to_der().unwrap(),
        }
    }

    /// Extract an inner openssl PKey, or panic if the key is another type.
    fn as_openssl_pkey(&self) -> &PKey<Private> {
        #[allow(unreachable_patterns)]
        match &self.0 {
            OpensslKey::Rsa(k) => k,
            _ => panic!("wrong key type"),
        }
    }
}

/// An X509 TLS certificate.
#[derive(Clone)]
pub struct Cert(X509);

impl Cert {
    /// Output the certificate in DER format.
    pub fn to_der(&self) -> Vec<u8> {
        self.0.to_der().unwrap()
    }

    /// Output the certificate in PEM format.
    pub fn to_pem(&self) -> Vec<u8> {
        self.0.to_pem().unwrap()
    }

    /// Parse a certificate from bytes in DER format.
    pub fn from_der(bytes: &[u8]) -> Self {
        Cert(X509::from_der(bytes).unwrap())
    }

    /// Parse a certificate from bytes in PEM format.
    pub fn from_pem(bytes: &[u8]) -> Self {
        Cert(X509::from_pem(bytes).unwrap())
    }
}

/// Certificate creation mode
pub enum CertMode {
    /// Certificate will be self-signed.
    SelfSigned,
    /// Certificate will be signed by another certificate's private key.
    WithIssuer(Cert, PrivateKey),
}

/// A helper object for building certificates.
pub struct CertBuilder {
    subject_key: PrivateKey,
    mode: CertMode,
    builder: X509Builder,
}

impl CertBuilder {
    /// Start building a new certificate.
    pub fn new(subject_key: &PrivateKey, mode: CertMode) -> Self {
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_pubkey(subject_key.as_openssl_pkey()).unwrap();
        if let CertMode::WithIssuer(issuer_cert, _) = &mode {
            builder
                .set_issuer_name(issuer_cert.0.subject_name())
                .unwrap();
        }
        Self {
            subject_key: subject_key.clone(),
            mode,
            builder,
        }
    }

    /// Add a subject name using the [`NameBuilder`] interface.
    pub fn subject<F: Fn(&mut NameBuilder)>(mut self, func: F) -> Self {
        let mut nb = NameBuilder::new();
        func(&mut nb);
        let name = nb.build();
        self.builder.set_subject_name(&name).unwrap();
        if matches!(self.mode, CertMode::SelfSigned) {
            self.builder.set_issuer_name(&name).unwrap();
        }
        self
    }

    /// Add a subject common name.
    pub fn subject_common_name(self, name: &str) -> Self {
        self.subject(|name_builder| {
            name_builder.common_name(name);
        })
    }

    /// Add a `KeyUsage` extension that's appropriate for a CA.
    ///
    /// See cabforum baseline requirements 7.1.2.1.b, 7.1.2.2.e.
    ///
    pub fn key_usage_ca(mut self) -> Self {
        let ext = extension::KeyUsage::new()
            .digital_signature()
            .key_cert_sign()
            .build()
            .unwrap();
        self.builder.append_extension(ext).unwrap();
        self
    }

    /// Build a `KeyUsage` that's appropriate for an end-entity.
    ///
    /// See cabforum baseline requirements 7.1.2.3.
    ///
    pub fn key_usage_entity(mut self) -> Self {
        let ext = extension::KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()
            .unwrap();
        self.builder.append_extension(ext).unwrap();
        self
    }

    /// Set the certificate validity time.
    ///
    /// The certificate will be valid from now until the specified number of
    /// days in the future.
    pub fn cert_validity(mut self, days: u32) -> Self {
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(days).unwrap();
        self.builder.set_not_before(&not_before).unwrap();
        self.builder.set_not_after(&not_after).unwrap();
        self
    }

    /// Set the certificate serial number.
    ///
    /// The input bytes are interpreted as one large big-endian integer.
    pub fn serial_number(mut self, serial_bytes: &[u8]) -> Self {
        let serial_number = BigNum::from_slice(serial_bytes).unwrap();
        let serial_number = Asn1Integer::from_bn(&serial_number).unwrap();
        self.builder.set_serial_number(&serial_number).unwrap();
        self
    }

    /// Set the basic constraints extension for a CA root certificate.
    pub fn basic_constraints_ca_root(mut self) -> Self {
        let basic_constraints = extension::BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .unwrap();
        self.builder.append_extension(basic_constraints).unwrap();
        self
    }

    /// Set the basic constraints extension for a CA intermediate certificate.
    ///
    /// The `path_length` indicates how many more CA certificates can exist
    /// between this certificate and the end-entity certificate. If `path_length`
    /// is set to `0`, then this certificate cannot be used to sign additional
    /// CA certificates.
    ///
    pub fn basic_constraints_intermediate(mut self, path_length: usize) -> Self {
        // Set the path length to 0, meaning this certificate can't be used
        // to sign additional CA certificates.
        let basic_constraints = extension::BasicConstraints::new()
            .critical()
            .ca()
            .pathlen(path_length.try_into().unwrap())
            .build()
            .unwrap();
        self.builder.append_extension(basic_constraints).unwrap();
        self
    }

    /// Set the basic constraints extension for an end-entity certificate.
    pub fn basic_constraints_entity(mut self) -> Self {
        let basic_constraints = extension::BasicConstraints::new()
            .critical()
            .build()
            .unwrap();
        self.builder.append_extension(basic_constraints).unwrap();
        self
    }

    /// Add a Subject Alternative Name field containing a DNS name.
    ///
    /// This is required for most server certificates.
    pub fn subject_alternative_name_dns(mut self, name: &str) -> Self {
        let issuer_cert = match &self.mode {
            CertMode::SelfSigned => None,
            CertMode::WithIssuer(issuer_cert, _) => Some(issuer_cert.0.as_ref()),
        };

        let context = self.builder.x509v3_context(issuer_cert, None);
        let subject_alt_name = extension::SubjectAlternativeName::new()
            .critical()
            .dns(name)
            .build(&context)
            .unwrap();
        self.builder.append_extension(subject_alt_name).unwrap();
        self
    }

    /// Add a Subject Alternative Name field containing an email address.
    ///
    /// This might be useful in a client certificate.
    pub fn subject_alternative_name_email(mut self, email: &str) -> Self {
        let issuer_cert = match &self.mode {
            CertMode::SelfSigned => None,
            CertMode::WithIssuer(issuer_cert, _) => Some(issuer_cert.0.as_ref()),
        };

        let context = self.builder.x509v3_context(issuer_cert, None);
        let subject_alt_name = extension::SubjectAlternativeName::new()
            .critical()
            .email(email)
            .build(&context)
            .unwrap();
        self.builder.append_extension(subject_alt_name).unwrap();
        self
    }

    /// Add a Subject Alternative Name field containing a serial number.
    ///
    /// This might be useful in a client certificate.
    pub fn subject_alternative_name_raw(mut self, raw: &[u8]) -> Self {
        let der_bytes = Asn1OctetString::new_from_bytes(raw).unwrap();

        let oid = Asn1Object::from_str("2.5.29.17").unwrap();

        let ext = X509Extension::new_from_der(&oid, true, &der_bytes).unwrap();
        self.builder.append_extension(ext).unwrap();
        self
    }

    /// Add the Subject Key Identifier and Authority Key Identifier extensions.
    ///
    /// In a self-signed certificate, these values will be the same.
    ///
    pub fn key_identifiers(mut self) -> Self {
        match &self.mode {
            CertMode::SelfSigned => {
                // Note: For self-signed certs, SubjectKeyIdentifier must be stored first,
                // before AuthorityKeyIdentifier can succeed.
                // The first `None` passed to `x509v3_context` indicates a self-signed cert.
                let context = self.builder.x509v3_context(None, None);
                let subject_key_id = extension::SubjectKeyIdentifier::new()
                    .build(&context)
                    .unwrap();
                self.builder.append_extension(subject_key_id).unwrap();
                let context = self.builder.x509v3_context(None, None);
                let authority_key_id = extension::AuthorityKeyIdentifier::new()
                    .keyid(true)
                    .build(&context)
                    .unwrap();
                self.builder.append_extension(authority_key_id).unwrap();
            }
            CertMode::WithIssuer(issuer_cert, _) => {
                let context = self.builder.x509v3_context(Some(&issuer_cert.0), None);
                let authority_key_id = extension::AuthorityKeyIdentifier::new()
                    .keyid(true)
                    .build(&context)
                    .unwrap();
                let subject_key_id = extension::SubjectKeyIdentifier::new()
                    .build(&context)
                    .unwrap();
                self.builder.append_extension(authority_key_id).unwrap();
                self.builder.append_extension(subject_key_id).unwrap();
            }
        }
        self
    }

    /// Add an Extended Key Usage extension to a server certificate.
    pub fn extended_key_usage_server(mut self) -> Self {
        let ext_key_usage = extension::ExtendedKeyUsage::new()
            .critical()
            .server_auth()
            .build()
            .unwrap();
        self.builder.append_extension(ext_key_usage).unwrap();
        self
    }

    /// Add an Extended Key Usage extension to a client certificate.
    pub fn extended_key_usage_client(mut self) -> Self {
        let ext_key_usage = extension::ExtendedKeyUsage::new()
            .critical()
            .client_auth()
            .build()
            .unwrap();
        self.builder.append_extension(ext_key_usage).unwrap();
        self
    }

    /// Consume the builder and return a signed certificate.
    pub fn finish(mut self) -> Cert {
        let signing_key = match &self.mode {
            CertMode::SelfSigned => &self.subject_key,
            CertMode::WithIssuer(_, issuer_key) => issuer_key,
        };
        let issuer_key = signing_key.as_openssl_pkey();
        self.builder
            .sign(issuer_key, MessageDigest::sha256())
            .unwrap();
        Cert(self.builder.build())
    }

    /// Consume the builder and return a certificate with a bad signature.
    ///
    /// The certificate will be signed by a randomly generated key, rather
    /// than the one that was expected.
    pub fn finish_bad_signature(mut self) -> Cert {
        let bad_key = PrivateKey::new_rsa();
        let bad_key = bad_key.as_openssl_pkey();
        self.builder.sign(bad_key, MessageDigest::sha256()).unwrap();
        Cert(self.builder.build())
    }
}

/// Create a new self-signed root CA certificate.
pub fn create_root_cert(key: &PrivateKey) -> Cert {
    CertBuilder::new(key, CertMode::SelfSigned)
        .subject(|name| {
            name.organization("Test CA").common_name("Test CA Root");
        })
        // Make the certificate valid for 20 years.
        .cert_validity(365 * 20)
        // Give the certificate a fixed 16-byte serial number.
        .serial_number(b"----test-root-ca")
        .basic_constraints_ca_root()
        .key_usage_ca()
        .key_identifiers()
        .finish()
}

/// Create a new intermediate CA certificate.
pub fn create_intermediate_cert(
    issuer_key: &PrivateKey,
    issuer_cert: &Cert,
    subject_key: &PrivateKey,
) -> Cert {
    CertBuilder::new(
        subject_key,
        CertMode::WithIssuer(issuer_cert.clone(), issuer_key.clone()),
    )
    .subject(|name| {
        name.organization("Test CA")
            .common_name("Test CA Intermediate 1");
    })
    .cert_validity(365 * 20)
    .serial_number(b"---test-intm-ca1")
    .basic_constraints_intermediate(0)
    .key_usage_ca()
    .key_identifiers()
    .finish()
}

/// Create a server certificate.
pub fn create_server_cert(
    issuer_key: &PrivateKey,
    issuer_cert: &Cert,
    subject_key: &PrivateKey,
) -> Cert {
    CertBuilder::new(
        subject_key,
        CertMode::WithIssuer(issuer_cert.clone(), issuer_key.clone()),
    )
    .subject_common_name("test-server")
    .cert_validity(365 * 20)
    // Give the certificate a fixed 16-byte serial number.
    .serial_number(b"test-server-cert")
    .basic_constraints_entity()
    .subject_alternative_name_dns("test-server")
    .key_usage_entity()
    .extended_key_usage_server()
    .key_identifiers()
    .finish()
}

/// Create a client certificate.
pub fn create_client_cert(
    issuer_key: &PrivateKey,
    issuer_cert: &Cert,
    subject_key: &PrivateKey,
) -> Cert {
    CertBuilder::new(
        subject_key,
        CertMode::WithIssuer(issuer_cert.clone(), issuer_key.clone()),
    )
    .subject_common_name("test@example.com")
    .cert_validity(365 * 20)
    // Give the certificate a fixed 16-byte serial number.
    .serial_number(b"test-client-cert0")
    .basic_constraints_entity()
    .subject_alternative_name_email("test@example.com")
    .key_usage_entity()
    .extended_key_usage_client()
    .key_identifiers()
    .finish()
}

pub struct NameBuilder {
    inner: X509NameBuilder,
}

impl NameBuilder {
    fn new() -> Self {
        Self {
            inner: X509NameBuilder::new().unwrap(),
        }
    }

    fn build(self) -> X509Name {
        self.inner.build()
    }

    pub fn common_name(&mut self, name: &str) -> &mut Self {
        self.inner
            .append_entry_by_nid(Nid::COMMONNAME, name)
            .unwrap();
        self
    }

    pub fn organization(&mut self, name: &str) -> &mut Self {
        self.inner
            .append_entry_by_nid(Nid::ORGANIZATIONNAME, name)
            .unwrap();
        self
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn make_certs() {
        let root_key = PrivateKey::new_rsa();
        let root_cert = create_root_cert(&root_key);
        let intermediate_key = PrivateKey::new_rsa();
        let intermediate_cert = create_intermediate_cert(&root_key, &root_cert, &intermediate_key);
        let server_key = PrivateKey::new_rsa();
        let _server_cert = create_server_cert(&intermediate_key, &intermediate_cert, &server_key);
        let client_key = PrivateKey::new_rsa();
        let _client_cert = create_client_cert(&intermediate_key, &intermediate_cert, &client_key);
    }
}
