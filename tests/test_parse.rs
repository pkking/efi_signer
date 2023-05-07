use efi_signer;
use env_logger;

pub fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn test_parse_pe() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi");
    let pe = efi_signer::EfiImage::parse(efi_buf);
    assert!(pe.is_ok());
}

#[test]
fn test_parse_invalid_pe() {
    init();
    let efi_buf = include_bytes!("./invalid.efi");
    let pe = efi_signer::EfiImage::parse(efi_buf);
    assert!(pe.is_err());
}

#[test]
fn test_check_sum_compute() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();

    let cksm = pe.compute_check_sum().unwrap();
    let inline_cksm = pe.get_checksum_from_header().unwrap();

    assert_eq!(cksm, inline_cksm);
}

#[test]
fn test_get_digest_algo() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi.signed");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();
    assert_eq!(
        pe.get_digest_algo().unwrap().unwrap(),
        efi_signer::DigestAlgorithm::Sha256
    );
}

#[test]
fn test_get_digest() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi.signed");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();

    assert_eq!(
        pe.compute_digest(efi_signer::DigestAlgorithm::Sha256)
            .unwrap(),
        pe.get_digest().unwrap().unwrap()
    );
}

#[test]
fn test_get_cert_table() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi.signed");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();

    assert!(pe.signatures.len() == 1);
}

#[test]
fn test_get_cert_table_dual() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi.dualsigned");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();

    assert!(pe.signatures.len() == 2);
}

#[test]
fn test_get_cert_table_non() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();

    assert!(pe.signatures.len() == 0);
}