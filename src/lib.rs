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
#![feature(cursor_remaining, buf_read_has_data_left)]
#![feature(error_generic_member_access)]
#![feature(provide_any)]
use crate::error::{
    AlgorithmSnafu, AuthenticodeSnafu, CertDecodeSnafu, ConvertPEM2PKCS7Snafu,
    InvalidMagicInOptHdrSnafu, MissingOptHdrSnafu, NoDigestAlgoSnafu, OpenFileSnafu, PESnafu,
    ParseCertificateSnafu, ParseImageSnafu, ParsePrivateKeySnafu, PemDecodeSnafu, PemFileSnafu,
    ReadBtyeSnafu, ReadLeftDataSnafu, Result, WinCertSnafu, WriteBtyeSnafu,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use core::slice;
use digest::DynDigest;
use error::{AuthenticodeVerifySnafu, CtlFetchSnafu, PemDecodeFromUTF8Snafu, ReadFileSnafu};
use goblin::pe::data_directories::SIZEOF_DATA_DIRECTORY;
use goblin::pe::header::{PE_MAGIC, SIZEOF_COFF_HEADER, SIZEOF_PE_MAGIC};
use goblin::pe::optional_header::{
    MAGIC_32, MAGIC_64, SIZEOF_STANDARD_FIELDS_32, SIZEOF_STANDARD_FIELDS_64,
    SIZEOF_WINDOWS_FIELDS_32, SIZEOF_WINDOWS_FIELDS_64,
};
use goblin::pe::section_table::SectionTable;
use goblin::pe::{data_directories::DataDirectory, PE};
use log::{debug, warn};
use picky::x509::Cert;

use openssl_sys::{
    c_void, BIO_get_mem_data, BIO_new, BIO_new_mem_buf, BIO_s_mem, NID_pkcs7_data,
    NID_pkcs7_signed, PEM_read_bio_X509, PEM_write_bio_PKCS7, PKCS7_add_certificate,
    PKCS7_content_new, PKCS7_new, PKCS7_set_type,
};
use picky::key::PrivateKey;
use picky::pem::Pem;
use picky::x509::date::UtcDate;
use picky::x509::pkcs7::authenticode::{AuthenticodeSignature, ShaVariant};
use picky::x509::pkcs7::{ctl, ctl::http_fetch::CtlHttpFetch, Pkcs7};
use picky::x509::wincert::{CertificateType, WinCertificate};

use snafu::{OptionExt, ResultExt};
use std::fmt::Display;
use std::fs::{read, File};
use std::io::{BufRead, BufReader, Cursor};
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::str;

pub mod error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub WinCertificate);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub offset: usize,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    MD5,
}

impl TryFrom<ShaVariant> for DigestAlgorithm {
    type Error = error::Error;

    fn try_from(value: ShaVariant) -> Result<DigestAlgorithm> {
        match value {
            ShaVariant::MD5 => Ok(DigestAlgorithm::MD5),
            ShaVariant::SHA1 => Ok(DigestAlgorithm::Sha1),
            ShaVariant::SHA2_256 => Ok(DigestAlgorithm::Sha256),
            _ => NoDigestAlgoSnafu.fail()?,
        }
    }
}

impl Display for DigestAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DigestAlgorithm::MD5 => write!(f, "MD5"),
            DigestAlgorithm::Sha1 => write!(f, "SHA1"),
            DigestAlgorithm::Sha256 => write!(f, "SHA256"),
        }
    }
}

#[derive(Debug)]
pub struct EfiImage<'a> {
    pub pe: Box<PE<'a>>,
    pub raw: Vec<u8>,
    pub checksum: Section,
    pub cert_table: Option<Section>,
    pub cert_data_directory: Section,
    pub overlay: Option<Vec<Section>>,
    pub signatures: Vec<Signature>,
    pub zero_padding: usize,
}

const CHECK_SUM_OFFSET: usize = 64; // offset from start of optional header to check sum filed
const SIZEOF_CHECKSUM: usize = mem::size_of::<u32>();
const CERT_TABLE_OFFSET: usize = 4 * mem::size_of::<DataDirectory>(); // offset from start of data directories to cert table direcotory
const SIZEOF_CERT_TABLE: usize = mem::size_of::<DataDirectory>();

impl Signature {
    /// encode the EFI signature into a Vec<u8>
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(self.0.clone().encode().context(WinCertSnafu {})?)
    }
    /// decode the a Vec<u8> into the EFI signature
    pub fn decode(buf: &[u8]) -> Result<Self> {
        Ok(Signature(
            WinCertificate::decode(buf).context(WinCertSnafu {})?,
        ))
    }
}
impl<'a> EfiImage<'a> {
    fn get_pem_from_file(certfile_path: &Path) -> Result<Pem<'a>> {
        let certfile = Pem::read_from(&mut BufReader::new(File::open(certfile_path).context(
            OpenFileSnafu {
                path: certfile_path.display().to_string(),
            },
        )?))
        .context(PemFileSnafu {
            path: certfile_path.display().to_string(),
        })?;

        Ok(certfile)
    }

    fn get_cert_table_addr(pe: &PE) -> Result<Option<DataDirectory>> {
        Ok(*pe
            .header
            .optional_header
            .context(MissingOptHdrSnafu {})?
            .data_directories
            .get_certificate_table())
    }

    fn get_cert_table_section(pe: &PE, pe_raw: &[u8]) -> Result<Section> {
        let dd = EfiImage::get_cert_table_addr(pe)?.context(MissingOptHdrSnafu {})?;

        Ok(Section {
            offset: dd.virtual_address as usize,
            data: pe_raw[dd.virtual_address as usize..(dd.virtual_address + dd.size) as usize]
                .to_vec(),
        })
    }

    fn get_cert_table_offset(pe: &PE) -> Result<usize> {
        let hdr = pe.header.optional_header.context(MissingOptHdrSnafu {})?;
        // get size of |< -- >|
        let offset = match hdr.standard_fields.magic {
            MAGIC_32 => {
                SIZEOF_WINDOWS_FIELDS_32 + SIZEOF_STANDARD_FIELDS_32
                    - CHECK_SUM_OFFSET
                    - SIZEOF_CHECKSUM
                    + CERT_TABLE_OFFSET
            }
            MAGIC_64 => {
                SIZEOF_WINDOWS_FIELDS_64 + SIZEOF_STANDARD_FIELDS_64
                    - CHECK_SUM_OFFSET
                    - SIZEOF_CHECKSUM
                    + CERT_TABLE_OFFSET
            }
            _ => InvalidMagicInOptHdrSnafu {
                magic: hdr.standard_fields.magic,
            }
            .fail()?,
        };
        Ok(offset)
    }

    fn get_check_sum_offset(pe: &PE) -> usize {
        // check_sum offset = pe_signature addr + sizeof pe signature + sizeof PE_Header
        let mut offset =
            pe.header.dos_header.pe_pointer as usize + SIZEOF_PE_MAGIC + SIZEOF_COFF_HEADER;

        offset += CHECK_SUM_OFFSET;
        offset
    }

    fn get_check_sum_section(pe: &PE, pe_raw: &[u8]) -> Result<Section> {
        let checksum_offset = EfiImage::get_check_sum_offset(pe);
        Ok(Section {
            offset: checksum_offset,
            data: pe_raw[checksum_offset..checksum_offset + mem::size_of::<u32>()].to_vec(),
        })
    }

    fn get_dd_offset(pe: &PE) -> Result<usize> {
        Ok(EfiImage::get_check_sum_offset(pe)
            + SIZEOF_CHECKSUM
            + EfiImage::get_cert_table_offset(pe)?)
    }

    fn get_cert_dd_secion(pe: &PE, pe_raw: &[u8]) -> Result<Section> {
        let cert_dd_offset = EfiImage::get_dd_offset(pe)?;
        Ok(Section {
            offset: cert_dd_offset,
            data: pe_raw[cert_dd_offset..cert_dd_offset + SIZEOF_CERT_TABLE].to_vec(),
        })
    }
    /// convert a PEM formatted ceritificate into pkcs7 signedData format
    ///
    /// # Examples
    /// ```no_run
    /// use std::io::Write;
    ///
    /// let pem_file_content = std::fs::read("cert.pem").unwrap();
    /// let pem_str = std::str::from_utf8(&pem_file_content).unwrap();
    ///
    /// let p7 = efi_signer::EfiImage::pem_to_p7(&pem_file_content).unwrap();
    ///
    /// let mut file = std::fs::File::create("cert.p7b").unwrap();
    /// file.write_all(&p7).unwrap();
    /// ```
    pub fn pem_to_p7(buf: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let p7 = PKCS7_new();
            if p7.is_null() {
                return ConvertPEM2PKCS7Snafu {
                    reason: "failed to init a new PKCS7 struct",
                }
                .fail()?;
            }

            if PKCS7_set_type(p7, NID_pkcs7_signed) == 0 {
                return ConvertPEM2PKCS7Snafu {
                    reason: "failed to PKCS7_set_type",
                }
                .fail()?;
            }

            if PKCS7_content_new(p7, NID_pkcs7_data) == 0 {
                return ConvertPEM2PKCS7Snafu {
                    reason: "failed to PKCS7_content_new",
                }
                .fail()?;
            }

            let b = BIO_new_mem_buf(buf.as_ptr() as *const c_void, buf.len() as i32);
            if b.is_null() {
                return ConvertPEM2PKCS7Snafu {
                    reason: "failed to create bio buffer",
                }
                .fail()?;
            }

            let x509 = PEM_read_bio_X509(b, null_mut(), None, null_mut());
            if x509.is_null() {
                return ConvertPEM2PKCS7Snafu {
                    reason: "failed to read x509 from buffer",
                }
                .fail()?;
            }

            if PKCS7_add_certificate(p7, x509) == 0 {
                return ConvertPEM2PKCS7Snafu {
                    reason: "failed to add cert",
                }
                .fail()?;
            }

            let out = BIO_new(BIO_s_mem());
            if out.is_null() {
                return ConvertPEM2PKCS7Snafu {
                    reason: "failed to create output buffer",
                }
                .fail()?;
            }

            if PEM_write_bio_PKCS7(out, p7) == 0 {
                return ConvertPEM2PKCS7Snafu {
                    reason: "failed to write pkcs7 back to buffer",
                }
                .fail()?;
            }

            let mut ptr = null_mut();
            let len = BIO_get_mem_data(out, &mut ptr);
            Ok(slice::from_raw_parts(ptr as *const _ as *const _, len as usize).to_vec())
        }
    }

    fn check_sum(mut checksum: u32, data: &[u8], mut steps: usize) -> Result<u32> {
        if steps > 0 {
            let mut rdr = Cursor::new(data);
            let mut sum: u32;
            loop {
                sum = rdr.read_u16::<LittleEndian>().context(ReadBtyeSnafu {
                    offset: rdr.position() as usize,
                    size: mem::size_of::<u16>(),
                })? as u32
                    + checksum;
                checksum = (sum & 0xffff) + (sum >> 16);
                steps -= 1;
                if steps == 0 {
                    break;
                }
            }
        }

        Ok(checksum + (checksum >> 16))
    }

    fn get_section_size(pe: &PE) -> usize {
        let mut size: usize = 0;
        for sec in pe.sections.iter() {
            size += sec.size_of_raw_data as usize;
        }

        size
    }

    fn get_overlay_section(pe: &PE, pe_raw: &[u8]) -> Result<Option<Vec<Section>>> {
        let hdr = pe.header.optional_header.context(MissingOptHdrSnafu {})?;
        let mut res: Vec<Section> = Vec::new();
        let file_size = pe_raw.len();
        let end_of_sections =
            EfiImage::get_section_size(pe) + hdr.windows_fields.size_of_headers as usize;

        if file_size < end_of_sections {
            ParseImageSnafu {
                reason: "file size lesser than header_size + section_size, corrupt headers.",
            }
            .fail()?
        }
        // no overlay
        if file_size == end_of_sections {
            return Ok(None);
        }
        // if we have a cert table
        if let Some(cert_dd) = EfiImage::get_cert_table_addr(pe)? {
            let overlay_offset =
                EfiImage::get_section_size(pe) + hdr.windows_fields.size_of_headers as usize;
            // 1st part of overlay section contains: <end_of_sections> - <start_of_attribute_cert_table>

            res.push(Section {
                offset: overlay_offset,
                data: pe_raw[overlay_offset..cert_dd.virtual_address as usize].to_vec(),
            });

            // 2nd part of overlay is <end_of_cert_table> - <end_of_file>
            // only if we have a cert table
            let overlay_2_offset = (cert_dd.virtual_address + cert_dd.size) as usize;
            res.push(Section {
                offset: overlay_2_offset,
                data: pe_raw[overlay_2_offset..].to_vec(),
            });
        } else {
            // if we donot have a cert table, will be only one overlay
            res.push(Section {
                offset: end_of_sections,
                data: pe_raw[end_of_sections..].to_vec(),
            });
        }
        Ok(Some(res))
    }

    /// sign a PE image hash with cert and key
    /// Note: the `certfile` and `private_key` should in PEM format
    /// the program_name specified programName in SpcSpOpusInfo which is optional
    pub fn do_sign_signature(
        file_hash: Vec<u8>,
        certfile: Vec<u8>,    // pem in utf-8
        private_key: Vec<u8>, // pem in utf-8
        program_name: Option<String>,
    ) -> Result<Signature> {
        let pkey =
            PrivateKey::from_pem_str(str::from_utf8(&private_key).context(PemDecodeSnafu {})?)
                .context(ParsePrivateKeySnafu {})?;
        let pkcs7 = Pkcs7::from_pem_str(str::from_utf8(&certfile).context(PemDecodeSnafu {})?)
            .context(ParseCertificateSnafu {})?;

        let authenticode_signature = AuthenticodeSignature::new(
            &pkcs7,
            file_hash.to_vec(),
            ShaVariant::SHA2_256,
            &pkey,
            program_name,
        )
        .context(AuthenticodeSnafu {})?;

        let raw_authenticode_signature = authenticode_signature
            .to_der()
            .context(AuthenticodeSnafu {})?;
        debug!(
            "a new signature created, size: {:#04x}",
            raw_authenticode_signature.len()
        );
        let wincert = WinCertificate::from_certificate(
            raw_authenticode_signature,
            CertificateType::WinCertTypePkcsSignedData,
        );

        Ok(Signature(wincert))
    }

    /// get the digest alogrithm from a PE struct
    /// If the PE struct does not contain a signature None is returned
    pub fn get_digest_algo(&self) -> Result<Option<DigestAlgorithm>> {
        match self.signatures.len() {
            0 => Ok(None),
            _ => {
                let code = AuthenticodeSignature::from_der(&self.signatures[0].0.get_certificate())
                    .context(AuthenticodeSnafu {})?;
                Ok(Some(DigestAlgorithm::try_from(
                    ShaVariant::try_from(code.0.digest_algorithms()[0].oid_asn1().clone())
                        .context(AlgorithmSnafu {})?,
                )?))
            }
        }
    }

    fn parse_cert_table(pe: &PE, raw: &'a [u8]) -> Result<(Vec<Signature>, Option<Section>)> {
        let mut res: Vec<Signature> = Vec::new();
        let mut rdr = Cursor::new(raw);
        let mut cert_table = None;

        if let Some(cert_table_addr) = EfiImage::get_cert_table_addr(pe)? {
            rdr.set_position(cert_table_addr.virtual_address as u64);
            let mut begin = cert_table_addr.virtual_address as usize;

            cert_table = Some(EfiImage::get_cert_table_section(pe, raw)?);
            // there maybe more than one signature
            // so we scan over all the cert table
            while rdr.has_data_left().context(ReadLeftDataSnafu {})? {
                // “length” indicating the length of the structure, include the header itself
                // so the length of the signed data should be length - 4 - 2 - 2
                let length = rdr.read_u32::<LittleEndian>().context(ReadBtyeSnafu {
                    offset: rdr.position() as usize,
                    size: mem::size_of::<u32>(),
                })?;

                // grab the signed-data directly from buffer
                // and move the position forward
                let mut sd_end = begin + length as usize;

                let cert_data = &raw[begin..sd_end];
                let wincert = WinCertificate::decode(cert_data).context(WinCertSnafu {})?;
                let code = AuthenticodeSignature::from_der(wincert.get_certificate())
                    .context(AuthenticodeSnafu {})?;
                //authenticode only contains one digest algorithm
                if code.0.digest_algorithms().len() != 1 {
                    ParseImageSnafu {
                        reason: format!(
                            "invalid digest algorithms numbers: {}",
                            code.0.digest_algorithms().len()
                        ),
                    }
                    .fail()?
                }

                if code.0.signer_infos().len() != 1 {
                    ParseImageSnafu {
                        reason: format!(
                            "invalid signer_info numbers: {}",
                            code.0.signer_infos().len()
                        ),
                    }
                    .fail()?
                }

                if code.0.digest_algorithms()[0] != code.0.signer_infos()[0].digest_algorithm.0 {
                    ParseImageSnafu{ reason: format!("digest algorithm not consistent: {:?} in sign_info but {:?} in signed data",  code.0.digest_algorithms()[0], code.0.signer_infos()[0].digest_algorithm.0)}.fail()?
                }
                res.push(Signature(wincert));
                //each wincert should aligned to a byte
                if sd_end % 8 != 0 {
                    sd_end = (sd_end / 8 + 1) * 8;
                }
                rdr.set_position(sd_end as u64);
                begin = sd_end;
            }
        }
        Ok((res, cert_table))
    }

    /// parse a binary data into a PE struct
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        let pe = Box::new(PE::parse(buf).context(PESnafu {})?);
        let mut rdr = Cursor::new(buf);

        rdr.set_position(pe.header.dos_header.pe_pointer as u64);
        let signature = rdr.read_u32::<LittleEndian>().context(ReadBtyeSnafu {
            offset: rdr.position() as usize,
            size: mem::size_of::<u32>(),
        })?;
        if signature != PE_MAGIC {
            ParseImageSnafu {
                reason: format!(
                    "pe magic check failed expect:{} actual:{}",
                    PE_MAGIC, signature
                ),
            }
            .fail()?
        }
        let (res, cert_table) = EfiImage::parse_cert_table(&pe, buf)?;

        let checksum = EfiImage::get_check_sum_section(&pe, buf)?;

        let cert_dd = EfiImage::get_cert_dd_secion(&pe, buf)?;

        let overlay = EfiImage::get_overlay_section(&pe, buf)?;

        let mut raw = buf.to_vec();
        // add some padding to end of the file so that the file size is byte aligned
        let mut padding = 0;
        if raw.len() % 8 != 0 {
            padding = (raw.len() / 8 + 1) * 8 - raw.len();
            debug!("zero-pad {} bytes", padding);
            raw.append(&mut vec![0u8; padding]);
        }
        Ok(EfiImage {
            pe,
            raw,
            cert_data_directory: cert_dd,
            checksum,
            cert_table,
            overlay,
            signatures: res,
            zero_padding: padding,
        })
    }
    /// get the PE checksum from the header
    pub fn get_checksum_from_header(&self) -> Result<u32> {
        let mut rdr = Cursor::new(&self.raw);
        rdr.set_position(self.checksum.offset as u64);
        Ok(rdr.read_u32::<LittleEndian>().context(ReadBtyeSnafu {
            offset: rdr.position() as usize,
            size: mem::size_of::<u32>(),
        })?)
    }
    /// get digest from EFI image
    pub fn get_digest(&self) -> Result<Option<Vec<u8>>> {
        let mut hashes = Vec::new();
        for sig in self.signatures.iter() {
            let code = AuthenticodeSignature::from_der(sig.0.get_certificate())
                .context(AuthenticodeSnafu {})?;
            let Some(hash) = code.file_hash() else {
                continue;
            };

            if !hashes.is_empty() && hash != hashes[0] {
                ParseImageSnafu {
                    reason: format!(
                        "signature with different hash {:x?} and {:x?}",
                        hash, hash[0]
                    ),
                }
                .fail()?
            }

            hashes.push(hash);
        }
        match hashes.len() {
            0 => Ok(None),
            _ => Ok(Some(hashes[0].clone())),
        }
    }

    /// follow the calculating the pe image hash guard in authenticode spec:
    /// checksum, certificate table data directory and attribute certificate table are excluded from the whole header
    /// all sections are included by sorting ASC order by PointerToRawData
    /// the data remain behind certificate table also included
    /// 1.    Load the image header into memory.
    /// 2.    Initialize a hash algorithm context.
    /// 3.    Hash the image header from its base to immediately before the start of the checksum address, as specified in Optional Header Windows-Specific Fields.
    /// 4.    Skip over the checksum, which is a 4-byte field.
    /// 5.    Hash everything from the end of the checksum field to immediately before the start of the Certificate Table entry, as specified in Optional Header Data Directories.
    /// 6.    Get the Attribute Certificate Table address and size from the Certificate Table entry. For details, see section 5.7 of the PE/COFF specification.
    /// 7.    Exclude the Certificate Table entry from the calculation and hash everything from the end of the Certificate Table entry to the end of image header, including Section Table (headers).The Certificate Table entry is 8 bytes long, as specified in Optional Header Data Directories.
    /// 8.    Create a counter called SUM_OF_BYTES_HASHED, which is not part of the signature. Set this counter to the SizeOfHeaders field, as specified in Optional Header Windows-Specific Field.
    /// 9.    Build a temporary table of pointers to all of the section headers in the image. The NumberOfSections field of COFF File Header indicates how big the table should be. Do not include any section headers in the table whose SizeOfRawData field is zero.
    /// 10.    Using the PointerToRawData field (offset 20) in the referenced SectionHeader structure as a key, arrange the table's elements in ascending order. In other words, sort the section headers in ascending order according to the disk-file offset of the sections.
    /// 11.    Walk through the sorted table, load the corresponding section into memory, and hash the entire section. Use the SizeOfRawData field in the SectionHeader structure to determine the amount of data to hash.
    /// 12.    Add the section’s SizeOfRawData value to SUM_OF_BYTES_HASHED.
    /// 13.    Repeat steps 11 and 12 for all of the sections in the sorted table.
    /// 14.    Create a value called FILE_SIZE, which is not part of the signature. Set this value to the image’s file size, acquired from the underlying file system. If FILE_SIZE is greater than SUM_OF_BYTES_HASHED, the file contains extra data that must be added to the hash. This data begins at the SUM_OF_BYTES_HASHED file offset, and its length is:
    /// (File Size) – ((Size of AttributeCertificateTable) + SUM_OF_BYTES_HASHED)
    /// Note: The size of Attribute Certificate Table is specified in the second ULONG value in the Certificate Table entry (32 bit: offset 132, 64 bit: offset 148) in Optional Header Data Directories.
    /// 15.    Finalize the hash algorithm context.
    #[allow(clippy::box_default)]
    pub fn compute_digest(&self, alg: DigestAlgorithm) -> Result<Vec<u8>> {
        let hdr = self
            .pe
            .header
            .optional_header
            .context(MissingOptHdrSnafu {})?;

        let mut hasher: Box<dyn DynDigest> = match alg {
            DigestAlgorithm::MD5 => Box::new(md5::Md5::default()),
            DigestAlgorithm::Sha1 => Box::new(sha1::Sha1::default()),
            DigestAlgorithm::Sha256 => Box::new(sha2::Sha256::default()),
        };

        // 3. hash the image header from its base to immediately before the start
        // of the checksum address
        let mut begin = 0;
        let mut offset = EfiImage::get_check_sum_offset(&self.pe);
        let before_checksum = &self.raw[begin..offset];
        debug!("hashed from [{:#04x} - {:#04x}]", begin, offset);
        hasher.update(before_checksum);

        // 4. skip over checksum field
        begin = offset + SIZEOF_CHECKSUM;
        // 5. hash everything from the end of the checksum filed to immediately before the
        // start of the certificate table entry
        offset = EfiImage::get_cert_table_offset(&self.pe)?;
        let after_checksum = &self.raw[begin..begin + offset];
        debug!("hashed from [{:#04x} - {:#04x}]", begin, begin + offset);
        hasher.update(after_checksum);

        // 7. exclude the certificate table entry from the calculation and hash everything from the
        // end of the certificate table entry to the end of image header, including section table
        begin = begin + offset + SIZEOF_CERT_TABLE;
        offset = hdr.windows_fields.size_of_headers as usize;
        let after_cert_table_dd = &self.raw[begin..offset];
        debug!("hashed from [{:#04x} - {:#04x}]", begin, offset);
        hasher.update(after_cert_table_dd);

        // 8. create a counter
        let mut sum_of_bytes_hashed = hdr.windows_fields.size_of_headers;
        // debug!("header size: {}", sum_of_bytes_hashed);
        // 9 build a temporary table of pointers to all of the section headers in the image.
        // Do not include any section headers in the table whose SizeOfRawData filed is zero
        let mut temp_tables: Vec<&SectionTable> = Vec::new();
        for t in self.pe.sections.iter() {
            if t.size_of_raw_data != 0 {
                temp_tables.push(t);
                //debug!("section added: {:?}", t);
            }
        }
        // 10 using the PointerToRawData filed in the referenced sectionHeader structure as a key
        // arrange the tables elementes in ascending order
        // 11 walk through the sorted table, load the corresponding section in to memory and hash then entire section
        // use the SizeOfRawData filed in to SectionHeader structure to determine the amount of data to hash
        // 12 add sections SizeOfRawData value to SUM_OF_BYTES_HASHED
        // 13 repeat steps 11 and 12 for all the sections
        temp_tables.sort_by(|&a, &b| a.pointer_to_raw_data.cmp(&b.pointer_to_raw_data));

        for sec in temp_tables {
            debug!(
                "hashed from [{:#04x} - {:#04x}]",
                sec.pointer_to_raw_data,
                sec.pointer_to_raw_data + sec.size_of_raw_data
            );
            hasher.update(
                &self.raw[sec.pointer_to_raw_data as usize
                    ..(sec.pointer_to_raw_data + sec.size_of_raw_data) as usize],
            );
            sum_of_bytes_hashed += sec.size_of_raw_data;
        }

        // 14 Create a value called FILE_SIZE, which is not part of the signature.
        // Set this value to the image’s file size, acquired from the underlying file system. If FILE_SIZE is greater than SUM_OF_BYTES_HASHED,
        // the file contains extra data that must be added to the hash. This data begins at the SUM_OF_BYTES_HASHED file offset, and its length is:
        // (File Size) – ((Size of AttributeCertificateTable) + SUM_OF_BYTES_HASHED)
        let file_size = self.raw.len();
        if file_size > sum_of_bytes_hashed as usize {
            if let Some(dd) = hdr.data_directories.data_directories[4] {
                debug!(
                    "hashed from [{:#04x} - {:#04x}]",
                    sum_of_bytes_hashed, dd.virtual_address
                );
                hasher.update(&self.raw[sum_of_bytes_hashed as usize..dd.virtual_address as usize]);
                debug!(
                    "hashed from [{:#04x} - {:#04x}]",
                    dd.virtual_address + dd.size,
                    file_size
                );
                hasher.update(&self.raw[(dd.virtual_address + dd.size) as usize..]);
            } else {
                debug!(
                    "hashed from [{:#04x} - {:#04x}]",
                    sum_of_bytes_hashed, file_size
                );
                hasher.update(&self.raw[sum_of_bytes_hashed as usize..]);
            }
        }

        Ok(hasher.finalize().to_vec())
    }

    fn update_cert_directory(&self, rva: u32, size: u32, res: &mut Vec<u8>) -> Result<()> {
        let dd_offset = EfiImage::get_dd_offset(&self.pe)?;
        // insert the data directory into origin pe
        let mut writer: Vec<u8> = Vec::new();

        writer
            .write_u32::<LittleEndian>(rva)
            .context(WriteBtyeSnafu {
                offset: writer.len(),
                size: mem::size_of::<u32>(),
            })?;
        writer
            .write_u32::<LittleEndian>(size)
            .context(WriteBtyeSnafu {
                offset: writer.len(),
                size: mem::size_of::<u32>(),
            })?;
        res.splice(
            dd_offset..(dd_offset + SIZEOF_DATA_DIRECTORY),
            writer.iter().cloned(),
        );
        debug!("new image total size: {:#04x}", res.len());
        Ok(())
    }

    pub fn get_pe_ref(&self) -> &PE {
        &self.pe
    }
    /// reference: https://www.cnblogs.com/concurrency/p/3926698.html
    /// notice: call this method need flush self.raw first
    pub fn compute_check_sum(&self) -> Result<u32> {
        let file_size = self.raw.len() - self.zero_padding;
        let checksum_offset = EfiImage::get_check_sum_offset(&self.pe);
        let checksum_steps = checksum_offset >> 1;
        let checksum_after_size = (file_size - checksum_offset - 4) >> 1;
        let checksum_after_offset = checksum_offset + 4;

        let mut checksum = EfiImage::check_sum(0, &self.raw[..checksum_offset], checksum_steps)?;
        debug!(
            "check_sum_compute: range from [{:#04x} - {:#04x}], checksum: {}",
            0, checksum_offset, checksum
        );

        checksum = EfiImage::check_sum(
            checksum,
            &self.raw[checksum_after_offset..],
            checksum_after_size,
        )?;
        debug!(
            "check_sum_compute: range from [{:#04x} - {:#04x}], checksum: {}",
            checksum_after_offset, checksum_after_size, checksum
        );

        if (file_size & 1) > 0 {
            checksum += self.raw[file_size - 1] as u32;
            debug!("check_sum_compute: append last byte, checksum {}", checksum)
        }

        debug!(
            "check_sum_compute: add size and checksum {} + {} = {}",
            file_size,
            checksum,
            file_size as u32 + checksum
        );

        Ok(file_size as u32 + checksum)
    }

    fn update_check_sum(res: &mut Vec<u8>) -> Result<()> {
        let temp_buf = res.clone();
        let temp_pe = EfiImage::parse(&temp_buf)?;
        let new_checksum = temp_pe.compute_check_sum()?;

        debug!("new checksum for new pe image: {}", new_checksum);

        let mut writer = Cursor::new(res);

        writer.set_position(temp_pe.checksum.offset as u64);
        writer
            .write_u32::<LittleEndian>(new_checksum)
            .context(WriteBtyeSnafu {
                offset: temp_pe.checksum.offset,
                size: mem::size_of::<u32>(),
            })?;
        Ok(())
    }

    /// embedded signatures into the image
    pub fn set_authenticode(&self, signatures: Vec<Signature>) -> Result<Vec<u8>> {
        let hdr = self
            .pe
            .header
            .optional_header
            .context(MissingOptHdrSnafu {})?;
        let mut res: Vec<u8>;
        let mut size: u32 = 0;
        let rva: u32;
        // already contain a signature, just append
        if let Some(dd) = hdr.data_directories.data_directories[4] {
            let mut end_of_signature: u32 = dd.virtual_address + dd.size;
            rva = dd.virtual_address;
            size = dd.size;
            debug!(
                "already has some signatures, old rva and size: {:#04x}/{:#04x}",
                rva, size
            );
            res = self.raw[..end_of_signature as usize].to_vec();
            //each wincert should aligned to a byte
            // if not, try to append some padding
            if end_of_signature % 8 != 0 {
                end_of_signature = (end_of_signature / 8 + 1) * 8;
            }
            let mut padding = end_of_signature - (dd.virtual_address + dd.size);
            size += padding;
            if padding > 0 {
                debug!("need padding {:#04x} bytes when sign a new sig", padding);
            }
            res.append(&mut vec![0u8; padding as usize]);
            // append all other signatures
            for sig in signatures.iter() {
                let mut code_raw = sig.0.clone().encode().context(WinCertSnafu {})?;
                debug!("append new signature, size: {:#04x}", code_raw.len());

                size += code_raw.len() as u32;
                res.append(&mut code_raw);
                // append some padding
                end_of_signature = res.len() as u32;
                if end_of_signature % 8 != 0 {
                    end_of_signature = (end_of_signature / 8 + 1) * 8;
                    padding = end_of_signature - res.len() as u32;
                    debug!("append new signature need padding {} bytes", padding);
                    res.append(&mut vec![0u8; padding as usize]);
                    size += padding;
                }
            }
            // if we have the second overlay, append it
            if let Some(ref s) = self.overlay {
                if s.len() == 2 {
                    debug!(
                        "append second overlay buffer from [{:#04x} - {:#04x}]",
                        s[1].offset,
                        s[1].offset + s[1].data.len()
                    );
                    res.append(&mut s[1].data.clone());
                    size += s[1].data.len() as u32;
                }
            }
        } else {
            debug!("no signatures before, add a new signature");
            // no signatures existed, just append to the end of the file
            res = self.raw.clone();
            rva = res.len() as u32;

            for sig in signatures.iter() {
                let mut padding: usize = 0;
                let mut tmp = sig.0.clone().encode().context(WinCertSnafu {})?;
                debug!("append new signature, size: {:#04x}", tmp.len());

                size += tmp.len() as u32;
                res.append(&mut tmp);
                // append some padding
                if tmp.len() % 8 != 0 {
                    padding = (tmp.len() / 8 + 1) * 8 - tmp.len();
                }
                size += padding as u32;
                res.append(&mut vec![0u8; padding]);
            }
        }
        debug!("new rva and size: {:#04x}/{:#04x}", rva, size);
        self.update_cert_directory(rva, size, &mut res)?;
        EfiImage::update_check_sum(&mut res)?;

        Ok(res)
    }

    /// how to verify a signature against its binary
    /// refer from microsoft authenticode_pe.docx
    pub fn verify(&self, cas: Vec<String>) -> Result<()> {
        let mut ca_names: Vec<Cert> = Vec::new();

        for p in cas.iter() {
            ca_names.push(
                Cert::from_pem_str(
                    &String::from_utf8(read(PathBuf::from(p)).context(ReadFileSnafu { path: p })?)
                        .context(PemDecodeFromUTF8Snafu {})?,
                )
                .context(CertDecodeSnafu {})?,
            );
        }

        let cas = ca_names.iter().map(|c| c.issuer_name()).collect::<Vec<_>>();
        let ctl = ctl::CertificateTrustList::fetch().context(CtlFetchSnafu {})?;
        // extracting and verify pkcs #7
        // certificate processing
        // timestamp processing
        //calculating the PE image hash
        let now = UtcDate::now();
        let file_hash =
            self.compute_digest(self.get_digest_algo()?.context(NoDigestAlgoSnafu {})?)?;
        for sig in self.signatures.iter() {
            let code = AuthenticodeSignature::from_der(&sig.0.get_certificate())
                .context(AuthenticodeSnafu {})?;
            let verfier: picky::x509::pkcs7::authenticode::AuthenticodeValidator =
                code.authenticode_verifier();
            verfier
                .ctl(&ctl)
                .require_basic_authenticode_validation(file_hash.clone())
                .require_not_after_check()
                .require_not_before_check()
                .require_ca_against_ctl_check()
                .exact_date(&now)
                .exclude_cert_authorities(&cas);
            verfier.verify().context(AuthenticodeVerifySnafu {})?;
        }

        Ok(())
    }

    pub fn sign_signature(
        &self,
        certfile: PathBuf,
        private_key: PathBuf,
        program_name: Option<String>,
        mut algo: DigestAlgorithm,
    ) -> Result<Vec<u8>> {
        if let Some(a) = self.get_digest_algo()? {
            warn!(
                "a digest algorithm:{} already existed, ignore input args {}",
                a, algo
            );
            algo = a;
        }

        let key_pem = EfiImage::get_pem_from_file(&private_key)?;
        let cert_pem = EfiImage::get_pem_from_file(&certfile)?;

        let file_hash = self.compute_digest(algo)?;

        let signature = EfiImage::do_sign_signature(
            file_hash.to_vec(),
            cert_pem.to_string().into_bytes(),
            key_pem.to_string().into_bytes(),
            program_name,
        )?;
        self.set_authenticode(vec![signature])
    }

    /// print some info about the PE struct
    pub fn print_info(&self) -> Result<()> {
        debug!("EFI image info:");
        debug!(
            "calculated sha256 {:x?}",
            self.compute_digest(DigestAlgorithm::Sha256)?
        );
        debug!("embedded sha256 digest {:x?}", self.get_digest());
        debug!("checksum {:#06x}", self.compute_check_sum()?);
        if let Some(ref o) = self.overlay {
            let mut tot_size = 0;
            for s in o.iter() {
                debug!(
                    "overlay from [{:#06x} - {:#06x}] size {:#06x}",
                    s.offset,
                    s.offset + s.data.len(),
                    s.data.len()
                );
                tot_size += s.data.len();
            }
            debug!("section total size: {:#04x}", tot_size);
        }
        if let Some(ref c) = self.cert_table {
            debug!(
                "the attribute certificate table: [{:#06x} - {:#06x}]",
                c.offset,
                c.offset + c.data.len()
            );
        }

        let hdr = self
            .pe
            .header
            .optional_header
            .context(MissingOptHdrSnafu {})?;
        if let Some(dd) = hdr.data_directories.data_directories[4] {
            debug!(
                "pe the certificate data info: [{:#06x} - {:#06x}]",
                dd.virtual_address,
                dd.virtual_address + dd.size
            );
        }

        if let Some(algo) = self.get_digest_algo()? {
            debug!("digest algo: {}", algo);
        }
        Ok(())
    }
}
