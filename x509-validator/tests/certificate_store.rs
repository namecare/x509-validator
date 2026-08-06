//! Certificate store lookup behaviour.

use x509_validator::store::{subject_key, CertificateStore};
use x509_validator::Certificate;
use x509_validator_testkit::{cert, self_signed_ca};

fn store_cert(subject_cn: &str) -> Certificate<'static> {
    cert(self_signed_ca(subject_cn))
}

#[test]
fn append_and_find_by_subject_round_trip() {
    let mut store = CertificateStore::new();
    let c = store_cert("subject-a");
    let key = subject_key(&c);
    store.append(c);

    let found = store.find_by_subject(&key);
    assert_eq!(found.len(), 1);
}

#[test]
fn find_by_subject_returns_empty_slice_for_unknown_subject() {
    let store: CertificateStore = CertificateStore::new();
    assert!(store.find_by_subject(b"nope").is_empty());
}

#[test]
fn two_certificates_sharing_a_subject_are_both_returned() {
    let a = store_cert("shared-subject");
    let b = store_cert("shared-subject");
    let key = subject_key(&a);

    let mut store = CertificateStore::new();
    store.append(a);
    store.append(b);

    let found = store.find_by_subject(&key);
    assert_eq!(found.len(), 2);
}

#[test]
fn from_iter_populates_store() {
    let c1 = store_cert("s1");
    let c2 = store_cert("s2");
    let key1 = subject_key(&c1);
    let key2 = subject_key(&c2);

    let store = CertificateStore::from_iter(vec![c1, c2]);
    assert_eq!(store.find_by_subject(&key1).len(), 1);
    assert_eq!(store.find_by_subject(&key2).len(), 1);
}
