//! Subject Alternative Names
//!
//! An example of generating custom Subject Alternative Name types, beyond
//! what the openssl crate allows.

use asn1::{oid, Asn1Writable, Explicit, ObjectIdentifier, SetOfWriter, Utf8String};

#[derive(asn1::Asn1Write, asn1::Asn1Read)]
struct Stringy<'a> {
    oid: ObjectIdentifier,
    s: Utf8String<'a>,
}

#[derive(asn1::Asn1Write)]
struct SetStringy<'a> {
    inner: SetOfWriter<'a, Stringy<'a>>,
}

/// A collection of names used in generating a Subject Alternative Name extension.
pub struct SubjectAltName {
    /// A common name.
    pub common_name: Option<String>,
    /// A serial number.
    pub serial_number: Option<String>,
    /// A role.
    pub role: Option<String>,
}

const OID_COMMON_NAME: ObjectIdentifier = oid!(2, 5, 4, 3);
const OID_SERIAL_NUMBER: ObjectIdentifier = oid!(2, 5, 4, 5);
const OID_ROLE: ObjectIdentifier = oid!(2, 5, 4, 72);

impl SubjectAltName {
    /// Return `SubjectAltName` contents as DER-encoded bytes.
    ///
    /// For use with openssl `X509Extension::new_from_der()`.
    pub fn as_asn1_bytes(&self) -> Option<Vec<u8>> {
        asn1::write_single(self).ok()
    }
}

impl Asn1Writable for SubjectAltName {
    fn write(&self, w: &mut asn1::Writer) -> asn1::WriteResult {
        w.write_element(&asn1::SequenceWriter::new(&|w| {
            if let Some(common_name) = &self.common_name {
                let common_name = [Stringy {
                    oid: OID_COMMON_NAME,
                    s: Utf8String::new(common_name),
                }];
                let common_name: Explicit<_, 4> = Explicit::new(SetStringy {
                    inner: SetOfWriter::new(&common_name),
                });
                w.write_element(&common_name)?;
            }
            if let Some(serial_number) = &self.serial_number {
                let serial = [Stringy {
                    oid: OID_SERIAL_NUMBER,
                    s: Utf8String::new(serial_number),
                }];
                let serial: Explicit<_, 4> = Explicit::new(SetStringy {
                    inner: SetOfWriter::new(&serial),
                });
                w.write_element(&serial)?;
            }
            if let Some(role) = &self.role {
                let role = [Stringy {
                    oid: OID_ROLE,
                    s: Utf8String::new(role),
                }];
                let role: Explicit<_, 4> = Explicit::new(SetStringy {
                    inner: SetOfWriter::new(&role),
                });
                w.write_element(&role)?;
            }
            Ok(())
        }))
    }
}
