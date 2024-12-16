use std::path::PathBuf;
use std::str::FromStr;

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

    assert!(pe.signatures.is_empty());
}

#[test]
fn test_verify_non_sig() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();

    let paths = vec!["./tests/certificate.pem".to_string()];
    match pe.verify(paths) {
        Ok(_) => panic!("we should failed"),
        Err(e) => assert_eq!(e.to_string(), "No digest algorithm existed".to_string()),
    }
}

#[test]
fn test_verify_sig() {
    init();
    let buf = include_bytes!("./shimx64.efi");
    let pe = efi_signer::EfiImage::parse(buf).unwrap();

    let sig = pe
        .sign_signature(
            PathBuf::from_str("./tests/certificate.p7b").unwrap(),
            PathBuf::from_str("./tests/key.pem").unwrap(),
            None,
            efi_signer::DigestAlgorithm::Sha256,
        )
        .unwrap();

    let new_pe = efi_signer::EfiImage::parse(&sig).unwrap();
    let paths = vec!["./tests/certificate.pem".to_string()];
    match new_pe.verify(paths.clone()) {
        Ok(_) => println!("verify: Ok"),
        Err(e) => println!("verify: Failed(reason: {})", e),
    }
    // "verify should not failed"
    assert!(new_pe.verify(paths).is_ok(), "verify should not failed");
}

#[test]
fn test_verify_non_existed_cert() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();

    let paths = vec!["./tests/no_such.pem".to_string()];
    match pe.verify(paths) {
        Ok(_) => panic!("we should failed"),
        Err(e) => assert_eq!(
            e.to_string(),
            "Failed to read file ./tests/no_such.pem".to_string()
        ),
    }
}

#[test]
fn test_verify_invalid_cert() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();

    let paths = vec!["./tests/key.pem".to_string()];
    match pe.verify(paths) {
        Ok(_) => panic!("we should failed"),
        Err(e) => assert_eq!(
            true,
            e.to_string()
                .contains(&"Failed to decode a pem cert into Cert struct".to_string())
        ),
    }
}

#[test]
fn test_verify_wrong_cert() {
    init();
    let buf = include_bytes!("./shimx64.efi");
    let pe = efi_signer::EfiImage::parse(buf).unwrap();

    let sig = pe
        .sign_signature(
            PathBuf::from_str("./tests/certificate.p7b").unwrap(),
            PathBuf::from_str("./tests/key.pem").unwrap(),
            None,
            efi_signer::DigestAlgorithm::Sha256,
        )
        .unwrap();

    let new_pe = efi_signer::EfiImage::parse(&sig).unwrap();
    let paths = vec!["./tests/wrong_cert.pem".to_string()];
    match new_pe.verify(paths) {
        Ok(_) => panic!("we should failed"),
        Err(e) => assert_eq!(e.to_string(), "Failed to verify a authenticode".to_string()),
    }
}
