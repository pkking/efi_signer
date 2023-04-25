use picky::x509::wincert::WinCertificateError;
use picky_asn1_x509::algorithm_identifier::{UnsupportedAlgorithmError};
use picky::key::KeyError;
use picky::x509::pkcs7::Pkcs7Error;
use picky::x509::pkcs7::authenticode::AuthenticodeError;
use snafu::prelude::*;
use std::io::Error as IoError;
use picky::pem::PemError;
use goblin::error::Error as PeError;

pub type Result<T> = std::result::Result<T, Error>;


#[derive(Debug, Snafu)]
pub struct Error(InnerError);

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub(crate) enum InnerError {
    #[snafu(display("Decode failed"))]
    DecodeFromDer {},
    #[snafu(display("Failed to read file {path}"))]
    ReadFile {source: IoError, path: String},
    #[snafu(display("Failed to open file {path}"))]
    OpenFile {source: IoError, path: String},
    #[snafu(display("Failed to decode pem file {path}"))]
    PemFile {source: PemError, path: String},
    #[snafu(display("Missing optional header"))]
    MissingOptHdr {},
    #[snafu(display("Missing certificate table"))]
    MissingCertTbl {},
    #[snafu(display("Invalid magic:{magic} in optional header"))]
    InvalidMagicInOptHdr {magic: u16},
    #[snafu(display("Failed to read {size} byte from {offset}"))]
    ReadBtye {offset: usize, size: usize, source: IoError},
    #[snafu(display("Failed to write {size} byte from {offset}"))]
    WriteBtye {offset: usize, size: usize, source: IoError},
    #[snafu(display("Parse EFI image failed, reason: {reason}"))]
    ParseImage {reason: String},
    #[snafu(display("Parse private key failed, path: {path}"))]
    ParsePrivateKey {path: String, source: KeyError},
    #[snafu(display("Parse certificate failed, path: {path}"))]
    ParseCertificate {path: String, source: Pkcs7Error},
    #[snafu(display("Failed to sign the image, reason: {reason}"))]
    Sign {reason: String},
    #[snafu(display("Failed create a authenticode"))]
    Authenticode {source: AuthenticodeError},
    #[snafu(display("Invalid digest algorithm"))]
    Algorithm {source: UnsupportedAlgorithmError},
    #[snafu(display("Failed to read left data in buffer"))]
    ReadLeftData {source: IoError},
    #[snafu(display("Failed to decode to a wincert"))]
    WinCert {source: WinCertificateError},
    #[snafu(display("Failed to decode to a PE/COFF struct"))]
    PE {source: PeError},
    #[snafu(display("Failed to compute the digest"))]
    ComputeDigest {reason: String},
    #[snafu(display("No digest algorithm existed"))]
    NoDigestAlgo {},
}