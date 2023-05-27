# X509 Test Certificates

These crates exist to help your crate test TLS or HTTPS.

A lot of software doesn't test the tricky code paths like client certificate
authentication. One reason is that it's just too hard to generate realistic
certificates.

And why should you have to learn how to build realistic certificates? You're not
running a CA. There should just be a crate that offers pre-built certificates with
the properties you need.

```rust
use x509_test_certs::good_certs1 as certs;

let server_key = certs::SERVER_KEY_PEM;
let server_cert = certs::SERVER_CERT_PEM;
```

Pre-built test certificates can be found in the `x509-test-certs` crate. This crate
has zero dependencies, and doesn't even contain any code! It only holds const byte
arrays containing certificates and private keys.

# Generating certificates

Code for generating certificates can be found in the `x509-test-gen` crate. There is
limited flexibility right now, but this will improve in the future.

Future goals:
- More custom options for certificates.
- Elliptic curve keys and signatures.
- rustls support.
- Various flavors of "broken" certificates: expired, bad signatures, incorrect or
  missing extensions (non-CA signatures, bad path length, etc.)

Non-goals:
- Building or supporting a custom certificate authority. Running a CA requires a great deal more
  care than this crate takes. Please don't use any of the keys or certificates
  from these crates in real public services.

### License

The crates that contain code are released under the MIT license.

The `x509-test-certs` crate is released into the public domain. I don't think
cryptographic keys or X509 certificates are copyrightable, but even if they are,
you are allowed to do anything you want with them, including copying the
certificate files into your own project.


