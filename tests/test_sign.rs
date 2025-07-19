use std::path::PathBuf;
use std::str::FromStr;

fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}

#[test]
fn test_sign() {
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
    assert_eq!(
        new_pe.get_digest_algo().unwrap().unwrap(),
        efi_signer::DigestAlgorithm::Sha256
    );
    assert_eq!(
        pe.compute_digest(efi_signer::DigestAlgorithm::Sha256)
            .unwrap(),
        new_pe
            .compute_digest(efi_signer::DigestAlgorithm::Sha256)
            .unwrap()
    );
    assert_eq!(
        new_pe
            .compute_digest(efi_signer::DigestAlgorithm::Sha256)
            .unwrap(),
        new_pe.get_digest().unwrap().unwrap()
    );

    assert_eq!(
        new_pe.get_checksum_from_header().unwrap(),
        new_pe.compute_check_sum().unwrap()
    )
}

#[test]
fn test_sign_append() {
    init();
    let buf = include_bytes!("./shimx64.efi.signed");
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
    assert_eq!(
        new_pe.get_digest_algo().unwrap().unwrap(),
        efi_signer::DigestAlgorithm::Sha256
    );
    assert_eq!(
        pe.compute_digest(efi_signer::DigestAlgorithm::Sha256)
            .unwrap(),
        new_pe
            .compute_digest(efi_signer::DigestAlgorithm::Sha256)
            .unwrap()
    );
    assert_eq!(
        new_pe
            .compute_digest(efi_signer::DigestAlgorithm::Sha256)
            .unwrap(),
        new_pe.get_digest().unwrap().unwrap()
    );
    assert_eq!(new_pe.signatures.len(), 2);
    assert_eq!(
        new_pe.get_checksum_from_header().unwrap(),
        new_pe.compute_check_sum().unwrap()
    )
}

#[test]
fn test_do_sign_signature_invalid_cert_pem() {
    init();
    let file_hash = vec![0x01, 0x02, 0x03, 0x04];
    let invalid_cert_pem =
        b"-----BEGIN CERTIFICATE-----\nINVALID_CONTENT\n-----END CERTIFICATE-----".to_vec();
    let private_key = include_bytes!("./key.pem").to_vec();
    let program_name = None;
    let alog = efi_signer::DigestAlgorithm::Sha256;

    let result = efi_signer::EfiImage::do_sign_signature(
        file_hash,
        invalid_cert_pem,
        private_key,
        program_name,
        alog,
    );
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Parse certificate failed, invalid PEM provided: couldn't decode base64: Invalid symbol 95, offset 7."
    );
}

#[test]
fn test_do_sign_signature_invalid_private_key_pem() {
    init();
    let file_hash = vec![0x01, 0x02, 0x03, 0x04];
    let cert_pem = include_bytes!("./certificate.p7b").to_vec();
    let invalid_private_key =
        b"-----BEGIN PRIVATE KEY-----\nINVALID_CONTENT\n-----END PRIVATE KEY-----".to_vec();
    let program_name = None;
    let alog = efi_signer::DigestAlgorithm::Sha256;

    let result = efi_signer::EfiImage::do_sign_signature(
        file_hash,
        cert_pem,
        invalid_private_key,
        program_name,
        alog,
    );
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Parse private key failed, invalid PEM provided: couldn't decode base64: Invalid symbol 95, offset 7."
    );
}

#[test]
fn test_do_sign_signature_unsupported_digest_algo() {
    init();
    let file_hash = vec![0x01, 0x02, 0x03, 0x04];
    let cert_pem = include_bytes!("./certificate.p7b").to_vec();
    let private_key = include_bytes!("./key.pem").to_vec();
    let program_name = None;
    // Assuming MD5 is not supported for signing in AuthenticodeSignature
    let alog = efi_signer::DigestAlgorithm::MD5;

    let result = efi_signer::EfiImage::do_sign_signature(
        file_hash,
        cert_pem,
        private_key,
        program_name,
        alog,
    );
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Failed to create a authenticode: unsupported algorithm:  MD5"
    );
}
