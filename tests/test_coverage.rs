use std::path::PathBuf;
use std::str::FromStr;

pub fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn test_digest_algorithm_display() {
    init();
    assert_eq!(format!("{}", efi_signer::DigestAlgorithm::Sha1), "SHA1");
    assert_eq!(format!("{}", efi_signer::DigestAlgorithm::Sha256), "SHA256");
    assert_eq!(format!("{}", efi_signer::DigestAlgorithm::MD5), "MD5");
}

#[test]
fn test_signature_encode_decode() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi.signed");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();
    let signature = pe.signatures[0].clone();
    let encoded = signature.encode().unwrap();
    let decoded = efi_signer::Signature::decode(&encoded).unwrap();
    assert_eq!(signature, decoded);
}

#[test]
fn test_pems_to_p7() {
    init();
    let pem1 = include_bytes!("./certificate.pem").to_vec();
    let p7 = efi_signer::EfiImage::pems_to_p7(vec![pem1]).unwrap();
    assert!(!p7.is_empty());
}

#[test]
fn test_get_pe_ref() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();
    let pe_ref = pe.get_pe_ref();
    assert_eq!(pe.pe.header.coff_header.machine, pe_ref.header.coff_header.machine);
}

#[test]
fn test_print_info() {
    init();
    let efi_buf = include_bytes!("./shimx64.efi.signed");
    let pe = efi_signer::EfiImage::parse(efi_buf).unwrap();
    assert!(pe.print_info().is_ok());
}

#[test]
fn test_sign_with_program_name() {
    init();
    let buf = include_bytes!("./shimx64.efi");
    let pe = efi_signer::EfiImage::parse(buf).unwrap();

    let sig = pe
        .sign_signature(
            PathBuf::from_str("./tests/certificate.p7b").unwrap(),
            PathBuf::from_str("./tests/key.pem").unwrap(),
            Some("My Program".to_string()),
            efi_signer::DigestAlgorithm::Sha256,
        )
        .unwrap();

    let new_pe = efi_signer::EfiImage::parse(&sig).unwrap();
    assert!(new_pe.signatures.len() == 1);
}
