use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response};
use hyper_rustls::TlsAcceptor;
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::ServerConfig;
use x509_test_certs::good_certs1 as certs;

struct Server {
    addr: SocketAddr,
}

/// Spawn an https server with a trivial "Hello" endpoint.
///
/// The server will run forever, or until the tokio runtime exits.
async fn spawn_server(rustls_config: ServerConfig) -> Server {
    // Allocate a random port on localhost; remember the port number so
    // we can return it to the caller.
    let incoming = AddrIncoming::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = incoming.local_addr();
    let acceptor = TlsAcceptor::builder()
        .with_tls_config(rustls_config)
        .with_all_versions_alpn()
        .with_incoming(incoming);
    let service = make_service_fn(|_| async { Ok::<_, std::io::Error>(service_fn(hello)) });
    tokio::spawn(async move {
        hyper::Server::builder(acceptor)
            .serve(service)
            .await
            .unwrap();
    });

    Server { addr }
}

/// Endpoint for `spawn_server`.
async fn hello(_: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    Ok(Response::new(Body::from("Hello")))
}

/// A basic TLS server configuration.
fn basic_server_config() -> ServerConfig {
    // Get the server key and certificate.
    let key_der = certs::SERVER_KEY_DER.to_vec();
    let cert_der = certs::SERVER_CERT_DER.to_vec();
    let server_key = rustls::PrivateKey(key_der);
    let server_certs = vec![rustls::Certificate(cert_der)];

    // Configure rustls for the server.
    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(server_certs, server_key)
        .unwrap()
}

/// A TLS server configuration that requires a client certificate.
fn client_auth_config() -> ServerConfig {
    let root_cert_der = certs::ROOT_CERT_DER.to_vec();
    let key_der = certs::SERVER_KEY_DER.to_vec();
    let cert_der = certs::SERVER_CERT_DER.to_vec();
    let server_key = rustls::PrivateKey(key_der);
    let server_certs = vec![rustls::Certificate(cert_der)];

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_parsable_certificates(&[root_cert_der.clone()]);
    let client_cert_verifier = Arc::new(AllowAnyAuthenticatedClient::new(root_store));

    ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(server_certs, server_key)
        .unwrap()
}

/// A basic TLS server configuration.
fn bad_server_config() -> ServerConfig {
    use x509_test_certs::bad_certs1 as certs;

    // Get the server key and certificate.
    let key_der = certs::SERVER_KEY_DER.to_vec();
    let cert_der = certs::SERVER_CERT_DER.to_vec();
    let server_key = rustls::PrivateKey(key_der);
    let server_certs = vec![rustls::Certificate(cert_der)];

    // Configure rustls for the server.
    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(server_certs, server_key)
        .unwrap()
}

#[tokio::test]
async fn basic_https_test() {
    let server = spawn_server(basic_server_config()).await;

    let root_cert_der = certs::ROOT_CERT_DER.to_vec();
    let root_cert = reqwest::tls::Certificate::from_der(&root_cert_der).unwrap();

    let client = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(root_cert)
        .resolve(
            "test-server",
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .build()
        .unwrap();

    let result = client
        .get(format!("https://test-server:{}", server.addr.port()))
        .send()
        .await
        .unwrap();

    assert_eq!("Hello", result.bytes().await.unwrap());
}

#[tokio::test]
async fn https_client_auth() {
    let server = spawn_server(client_auth_config()).await;

    let root_cert_der = certs::ROOT_CERT_DER.to_vec();
    let root_cert = reqwest::tls::Certificate::from_der(&root_cert_der).unwrap();

    let key_pem = certs::CLIENT_KEY_PEM;
    let cert_pem = certs::CLIENT_CERT_PEM;
    let concatenated = [key_pem, cert_pem].concat();
    // This is a rustls-specific identity, so we must call
    // `.use_rustls_tls()` to build the reqwest Client.
    let identity = reqwest::Identity::from_pem(&concatenated).unwrap();

    let client = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .use_rustls_tls()
        .add_root_certificate(root_cert)
        .resolve(
            "test-server",
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .identity(identity)
        .build()
        .unwrap();

    let result = client
        .get(format!("https://test-server:{}", server.addr.port()))
        .send()
        .await
        .unwrap();

    assert_eq!("Hello", result.bytes().await.unwrap());
}

#[tokio::test]
async fn bad_https_test() {
    use x509_test_certs::bad_certs1 as certs;

    let server = spawn_server(bad_server_config()).await;

    let root_cert_der = certs::ROOT_CERT_DER.to_vec();
    let root_cert = reqwest::tls::Certificate::from_der(&root_cert_der).unwrap();

    let client = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(root_cert)
        .resolve(
            "test-server",
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .build()
        .unwrap();

    let result = client
        .get(format!("https://test-server:{}", server.addr.port()))
        .send()
        .await
        .unwrap_err();

    assert!(result.is_connect());
}
