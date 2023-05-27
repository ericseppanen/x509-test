//! # Pre-built X509 certificates.
//!
//! This crate provides cryptographic certificates and keys, meant for testing TLS
//! clients and servers.
//!
//! The certificates are meant to look realistic: they have most of the extensions that
//! real-world certificates have, and try to follow the CAB guidelines as a real CA would.
//!
//! This crate contains no code or dependencies, just `const` byte arrays containing
//! pre-generated certificates and private keys.
//!
//! If you would like to generate your own certificates, please try the `x509-test-gen`
//! crate. It contains the code that was used to generate the certificates in the
//! `x509-test-certs` crate.

pub mod good_certs1 {
    //! A collection of CA, client and server certificates.
    //!
    //! The certificates can be used to test successful client or server validation.
    //!
    //! The keys are RSA (2048 bit) and digests are SHA-256.
    //!
    //! The server certificate is for a dns name `test-server`. You may need
    //! to spoof dns or instruct your client to use this name.
    //!
    //! The client certificate is for an email address `test@example.com`.
    //!
    //! The client and server certificates share the same root certificate.
    //!
    // A quick test of these certificates:
    // openssl s_server -accept 9999 -cert server_cert.pem -key server_key.pem
    // openssl s_client -verify_return_error -connect localhost:9999 -CAfile root_cert.pem -verify_hostname test-server

    /// The root private key, in PEM format.
    pub const ROOT_KEY_PEM: &[u8] = include_bytes!("../static-certs/good_certs1/root_key.pem");
    /// The root private key, in DER format.
    pub const ROOT_KEY_DER: &[u8] = include_bytes!("../static-certs/good_certs1/root_key.der");
    /// The root certificate, in PEM format.
    pub const ROOT_CERT_PEM: &[u8] = include_bytes!("../static-certs/good_certs1/root_cert.pem");
    /// The root certificate, in DER format.
    pub const ROOT_CERT_DER: &[u8] = include_bytes!("../static-certs/good_certs1/root_cert.der");

    /// The server private key, in PEM format.
    pub const SERVER_KEY_PEM: &[u8] = include_bytes!("../static-certs/good_certs1/server_key.pem");
    /// The server private key, in DER format.
    pub const SERVER_KEY_DER: &[u8] = include_bytes!("../static-certs/good_certs1/server_key.der");
    /// The server certificate, in PEM format.
    pub const SERVER_CERT_PEM: &[u8] =
        include_bytes!("../static-certs/good_certs1/server_cert.pem");
    /// The server certificate, in DER format.
    pub const SERVER_CERT_DER: &[u8] =
        include_bytes!("../static-certs/good_certs1/server_cert.der");

    /// The client private key, in PEM format.
    pub const CLIENT_KEY_PEM: &[u8] = include_bytes!("../static-certs/good_certs1/client_key.pem");
    /// The client private key, in DER format.
    pub const CLIENT_KEY_DER: &[u8] = include_bytes!("../static-certs/good_certs1/client_key.der");
    /// The client certificate, in PEM format.
    pub const CLIENT_CERT_PEM: &[u8] =
        include_bytes!("../static-certs/good_certs1/client_cert.pem");
    /// The client certificate, in DER format.
    pub const CLIENT_CERT_DER: &[u8] =
        include_bytes!("../static-certs/good_certs1/client_cert.der");
}

pub mod good_certs2 {
    //! A collection of CA, intermediate, client and server certificates
    //!
    //! The certificates can be used to test successful client or server validation.
    //!
    //! The keys are RSA (2048 bit) and digests are SHA-256.
    //!
    //! The server certificate is for a dns name `test-server`. You may need
    //! to spoof dns or instruct your client to use this name.
    //!
    //! The client certificate is for an email address `test@example.com`.
    //!
    //! The client and server certificates share the same signature chain:
    //! ```txt
    //!        root
    //!         |
    //!    intermediate
    //!      /      \
    //!   client   server
    //! ```
    //!
    // A quick test of these certificates:
    // openssl s_client -verify_return_error -connect localhost:9999 -CAfile root_cert.pem -verify_hostname test-server -cert client_cert.pem -key client_key.pem
    // openssl s_server -accept 9999 -cert server_cert.pem -key server_key.pem -chainCAfile intermediate_cert.pem -verifyCAfile root_cert.pem -Verify 9

    /// The root private key, in PEM format.
    pub const ROOT_KEY_PEM: &[u8] = include_bytes!("../static-certs/good_certs2/root_key.pem");
    /// The root private key, in DER format.
    pub const ROOT_KEY_DER: &[u8] = include_bytes!("../static-certs/good_certs2/root_key.der");
    /// The root certificate, in PEM format.
    pub const ROOT_CERT_PEM: &[u8] = include_bytes!("../static-certs/good_certs2/root_cert.pem");
    /// The root certificate, in DER format.
    pub const ROOT_CERT_DER: &[u8] = include_bytes!("../static-certs/good_certs2/root_cert.der");

    /// The intermediate CA key, in PEM format.
    pub const INTERMEDIATE_KEY_PEM: &[u8] =
        include_bytes!("../static-certs/good_certs2/intermediate_key.pem");
    /// The intermediate CA key, in DER format.
    pub const INTERMEDIATE_KEY_DER: &[u8] =
        include_bytes!("../static-certs/good_certs2/intermediate_key.der");
    /// The intermediate CA certificate, in PEM format.
    pub const INTERMEDIATE_CERT_PEM: &[u8] =
        include_bytes!("../static-certs/good_certs2/intermediate_cert.pem");
    /// The intermediate CA certificate, in DER format.
    pub const INTERMEDIATE_CERT_DER: &[u8] =
        include_bytes!("../static-certs/good_certs2/intermediate_cert.der");

    /// The server private key, in PEM format.
    pub const SERVER_KEY_PEM: &[u8] = include_bytes!("../static-certs/good_certs2/server_key.pem");
    /// The server private key, in DER format.
    pub const SERVER_KEY_DER: &[u8] = include_bytes!("../static-certs/good_certs2/server_key.der");
    /// The server certificate, in PEM format.
    pub const SERVER_CERT_PEM: &[u8] =
        include_bytes!("../static-certs/good_certs2/server_cert.pem");
    /// The server certificate, in DER format.
    pub const SERVER_CERT_DER: &[u8] =
        include_bytes!("../static-certs/good_certs2/server_cert.der");

    /// The client private key, in PEM format.
    pub const CLIENT_KEY_PEM: &[u8] = include_bytes!("../static-certs/good_certs2/client_key.pem");
    /// The client private key, in DER format.
    pub const CLIENT_KEY_DER: &[u8] = include_bytes!("../static-certs/good_certs2/client_key.der");
    /// The client certificate, in PEM format.
    pub const CLIENT_CERT_PEM: &[u8] =
        include_bytes!("../static-certs/good_certs2/client_cert.pem");
    /// The client certificate, in DER format.
    pub const CLIENT_CERT_DER: &[u8] =
        include_bytes!("../static-certs/good_certs2/client_cert.der");
}

pub mod bad_certs1 {
    //! CA and improperly signed server certificates.
    //!
    //! The certificates can be used to test server validation failure.
    //!
    //! The keys are RSA (2048 bit) and digests are SHA-256.
    //!
    //! The server certificate is for a dns name `test-server`. You may need
    //! to spoof dns or instruct your client to use this name.
    //!
    //!

    /// The root private key, in PEM format.
    pub const ROOT_KEY_PEM: &[u8] = include_bytes!("../static-certs/bad_certs1/root_key.pem");
    /// The root private key, in DER format.
    pub const ROOT_KEY_DER: &[u8] = include_bytes!("../static-certs/bad_certs1/root_key.der");
    /// The root certificate, in PEM format.
    pub const ROOT_CERT_PEM: &[u8] = include_bytes!("../static-certs/bad_certs1/root_cert.pem");
    /// The root certificate, in DER format.
    pub const ROOT_CERT_DER: &[u8] = include_bytes!("../static-certs/bad_certs1/root_cert.der");

    /// The server private key, in PEM format.
    pub const SERVER_KEY_PEM: &[u8] = include_bytes!("../static-certs/bad_certs1/server_key.pem");
    /// The server private key, in DER format.
    pub const SERVER_KEY_DER: &[u8] = include_bytes!("../static-certs/bad_certs1/server_key.der");
    /// The server certificate, in PEM format.
    pub const SERVER_CERT_PEM: &[u8] = include_bytes!("../static-certs/bad_certs1/server_cert.pem");
    /// The server certificate, in DER format.
    pub const SERVER_CERT_DER: &[u8] = include_bytes!("../static-certs/bad_certs1/server_cert.der");
}
