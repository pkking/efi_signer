use efi_signer;
use env_logger;
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
            PathBuf::from_str("./certificate.p7b").unwrap(),
            PathBuf::from_str("./key.pem").unwrap(),
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
