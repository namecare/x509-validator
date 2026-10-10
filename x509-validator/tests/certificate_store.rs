//! Certificate store lookup behaviour.

use x509_validator::CertificateExt;
use x509_validator::store::CertificateStore;
use x509_validator_testkit::{cert, self_signed_ca};

/// The DER of a self-signed CA with the given subject.
///
/// A `Certificate` borrows the bytes it was parsed from, so the DER is
/// returned for the caller to own and `cert` is applied at the call site.
fn store_der(subject_cn: &str) -> Vec<u8> {
    self_signed_ca(subject_cn)
}

#[test]
fn append_and_find_by_subject_round_trip() {
    let mut store = CertificateStore::new();
    let c_der = store_der("subject-a");
    let c = cert(&c_der);
    let key = c.subject_key();
    store.append(c);

    let found = store.find_by_subject(&key);
    assert_eq!(found.len(), 1);
}

#[test]
fn find_by_subject_returns_empty_slice_for_unknown_subject() {
    let store: CertificateStore<'_> = CertificateStore::new();
    assert!(
        store
            .find_by_subject(b"nope")
            .is_empty()
    );
}

#[test]
fn two_certificates_sharing_a_subject_are_both_returned() {
    let a_der = store_der("shared-subject");
    let a = cert(&a_der);
    let b_der = store_der("shared-subject");
    let b = cert(&b_der);
    let key = a.subject_key();

    let mut store = CertificateStore::new();
    store.append(a);
    store.append(b);

    let found = store.find_by_subject(&key);
    assert_eq!(found.len(), 2);
}

#[test]
fn from_iter_populates_store() {
    let c1_der = store_der("s1");
    let c1 = cert(&c1_der);
    let c2_der = store_der("s2");
    let c2 = cert(&c2_der);
    let key1 = c1.subject_key();
    let key2 = c2.subject_key();

    let store = CertificateStore::from_iter(vec![c1, c2]);
    assert_eq!(store.find_by_subject(&key1).len(), 1);
    assert_eq!(store.find_by_subject(&key2).len(), 1);
}
