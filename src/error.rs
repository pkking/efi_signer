/*
 *
 *  * // Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  * //
 *  * // signatrust is licensed under Mulan PSL v2.
 *  * // You can use this software according to the terms and conditions of the Mulan
 *  * // PSL v2.
 *  * // You may obtain a copy of Mulan PSL v2 at:
 *  * //         http://license.coscl.org.cn/MulanPSL2
 *  * // THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 *  * // KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 *  * // NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *  * // See the Mulan PSL v2 for more details.
 *
 */
use der::Error as DerError;
use goblin::error::Error as PeError;
use picky::key::KeyError;
use picky::pem::PemError;
use picky::x509::certificate::CertError;
use picky::x509::pkcs7::authenticode::AuthenticodeError;
use picky::x509::pkcs7::ctl::CtlError;
use picky::x509::pkcs7::Pkcs7Error;
use picky::x509::wincert::WinCertificateError;
use picky_asn1_x509::algorithm_identifier::UnsupportedAlgorithmError;
use snafu::prelude::*;
use std::io::Error as IoError;
use std::str::Utf8Error;
use std::string::FromUtf8Error;

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
    ReadFile { source: IoError, path: String },
    #[snafu(display("Failed to open file {path}"))]
    OpenFile { source: IoError, path: String },
    #[snafu(display("Failed to decode pem file {path}"))]
    PemFile { source: PemError, path: String },
    #[snafu(display("Failed to fetch ctl from Microsoft"))]
    CtlFetch { source: CtlError },
    #[snafu(display("Missing optional header"))]
    MissingOptHdr {},
    #[snafu(display("Missing certificate table"))]
    MissingCertTbl {},
    #[snafu(display("Invalid magic:{magic} in optional header"))]
    InvalidMagicInOptHdr { magic: u16 },
    #[snafu(display("Failed to read {size} byte from {offset}"))]
    ReadBtye {
        offset: usize,
        size: usize,
        source: IoError,
    },
    #[snafu(display("Failed to write {size} byte from {offset}"))]
    WriteBtye {
        offset: usize,
        size: usize,
        source: IoError,
    },
    #[snafu(display("Parse EFI image failed, reason: {reason}"))]
    ParseImage { reason: String },
    #[snafu(display("PEM decode failed"))]
    PemDecode { source: Utf8Error },
    #[snafu(display("Parse private key failed"))]
    ParsePrivateKey { source: KeyError },
    #[snafu(display("Parse certificate failed"))]
    ParseCertificate { source: Pkcs7Error },
    #[snafu(display("Failed to sign the image, reason: {reason}"))]
    Sign { reason: String },
    #[snafu(display("Failed to create a authenticode"))]
    Authenticode { source: AuthenticodeError },
    #[snafu(display("Failed to verify a authenticode"))]
    AuthenticodeVerify { source: AuthenticodeError },
    #[snafu(display("Invalid digest algorithm"))]
    Algorithm { source: UnsupportedAlgorithmError },
    #[snafu(display("Failed to read left data in buffer"))]
    ReadLeftData { source: IoError },
    #[snafu(display("Failed to decode/encode to a wincert"))]
    WinCert { source: WinCertificateError },
    #[snafu(display("Failed to decode to a PE/COFF struct"))]
    PE { source: PeError },
    #[snafu(display("Failed to compute the digest"))]
    ComputeDigest { reason: String },
    #[snafu(display("No digest algorithm existed"))]
    NoDigestAlgo {},
    #[snafu(display("Not supported algorithm"))]
    NotSupportedAlgo {},
    #[snafu(display("Failed to decode a pem cert into Cert struct"))]
    CertDecode { source: CertError },
    #[snafu(display("Failed to decode PEM from utf8 str"))]
    PemDecodeFromUTF8 { source: FromUtf8Error },
    #[snafu(display("Failed to convert a pem cert to PKCS7 format"))]
    ConvertPEM2PKCS7 { source: DerError },
}
