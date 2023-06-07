use std::env::{current_dir, set_current_dir};

use x509_test_gen::san::SubjectAltName;
use x509_test_gen::{
    create_client_cert, create_intermediate_cert, create_root_cert, create_server_cert, Cert,
    CertBuilder, CertMode, PrivateKey,
};

macro_rules! write_pem_der {
    ($id:ident) => {
        ::std::fs::write(concat!(stringify!($id), ".pem"), $id.to_pem()).unwrap();
        ::std::fs::write(concat!(stringify!($id), ".der"), $id.to_der()).unwrap();
    };
}

fn main() {
    let start_dir = current_dir().unwrap();
    {
        let root_key = PrivateKey::new_rsa();
        let root_cert = create_root_cert(&root_key);
        let server_key = PrivateKey::new_rsa();
        let server_cert = create_server_cert(&root_key, &root_cert, &server_key);
        let client_key = PrivateKey::new_rsa();
        let client_cert = create_client_cert(&root_key, &root_cert, &client_key);

        set_current_dir("x509-test-certs/static-certs/good_certs1/").unwrap();
        write_pem_der!(root_key);
        write_pem_der!(root_cert);
        write_pem_der!(server_key);
        write_pem_der!(server_cert);
        write_pem_der!(client_key);
        write_pem_der!(client_cert);
    }

    {
        let root_key = PrivateKey::new_rsa();
        let root_cert = create_root_cert(&root_key);
        let intermediate_key = PrivateKey::new_rsa();
        let intermediate_cert = create_intermediate_cert(&root_key, &root_cert, &intermediate_key);
        let server_key = PrivateKey::new_rsa();
        let server_cert = create_server_cert(&intermediate_key, &intermediate_cert, &server_key);
        let client_key = PrivateKey::new_rsa();
        let client_cert = create_client_cert(&intermediate_key, &intermediate_cert, &client_key);

        set_current_dir(&start_dir).unwrap();
        set_current_dir("x509-test-certs/static-certs/good_certs2/").unwrap();
        write_pem_der!(root_key);
        write_pem_der!(root_cert);
        write_pem_der!(intermediate_key);
        write_pem_der!(intermediate_cert);
        write_pem_der!(server_key);
        write_pem_der!(server_cert);
        write_pem_der!(client_key);
        write_pem_der!(client_cert);
    }

    {
        let root_key = PrivateKey::new_rsa();
        let root_cert = create_root_cert(&root_key);
        let client_key = PrivateKey::new_rsa();
        let client_cert = create_advanced_client_cert(&root_key, &root_cert, &client_key);

        set_current_dir(&start_dir).unwrap();
        set_current_dir("x509-test-certs/static-certs/good_certs3/").unwrap();
        write_pem_der!(root_key);
        write_pem_der!(root_cert);
        write_pem_der!(client_key);
        write_pem_der!(client_cert);
    }

    {
        let root_key = PrivateKey::new_rsa();
        let root_cert = create_root_cert(&root_key);
        let server_key = PrivateKey::new_rsa();
        let server_cert =
            create_server_cert_with_invalid_signature(&root_key, &root_cert, &server_key);

        set_current_dir(&start_dir).unwrap();
        set_current_dir("x509-test-certs/static-certs/bad_certs1/").unwrap();
        write_pem_der!(root_key);
        write_pem_der!(root_cert);
        write_pem_der!(server_key);
        write_pem_der!(server_cert);
    }
}

fn create_server_cert_with_invalid_signature(
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
    .finish_bad_signature()
}

pub fn create_advanced_client_cert(
    issuer_key: &PrivateKey,
    issuer_cert: &Cert,
    subject_key: &PrivateKey,
) -> Cert {
    let san_bytes = SubjectAltName {
        common_name: Some("Client42".into()),
        serial_number: Some("sn10042".into()),
        role: Some("machine".into()),
    }
    .as_asn1_bytes()
    .unwrap();

    CertBuilder::new(
        subject_key,
        CertMode::WithIssuer(issuer_cert.clone(), issuer_key.clone()),
    )
    .subject_common_name("test@example.com")
    .cert_validity(365 * 20)
    // Give the certificate a fixed 16-byte serial number.
    .serial_number(b"test-client-cert0")
    .basic_constraints_entity()
    .subject_alternative_name_raw(&san_bytes)
    .key_usage_entity()
    .extended_key_usage_client()
    .key_identifiers()
    .finish()
}
