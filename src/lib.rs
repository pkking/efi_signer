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
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use digest::DynDigest;
use goblin::pe::data_directories::SIZEOF_DATA_DIRECTORY;
use goblin::pe::header::{PE_MAGIC, SIZEOF_COFF_HEADER, SIZEOF_PE_MAGIC};
use goblin::pe::optional_header::{
    MAGIC_32, MAGIC_64, SIZEOF_STANDARD_FIELDS_32, SIZEOF_STANDARD_FIELDS_64,
    SIZEOF_WINDOWS_FIELDS_32, SIZEOF_WINDOWS_FIELDS_64,
};
use goblin::pe::section_table::SectionTable;
use goblin::pe::{data_directories::DataDirectory, PE};
use md5;
use picky::key::PrivateKey;
use picky::pem::Pem;
use picky::x509::date::UtcDate;
use picky::x509::pkcs7::authenticode::{AuthenticodeSignature, ShaVariant};
use picky::x509::pkcs7::Pkcs7;
use picky::x509::wincert::{CertificateType, WinCertificate};
use sha1;
use sha2;
use snafu::{OptionExt, ResultExt};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor};
use std::mem;
use std::path::PathBuf;
use log::{info, warn, debug, error};
use crate::error::{NoDigestAlgoSnafu, ComputeDigestSnafu, PESnafu, WinCertSnafu, ReadLeftDataSnafu, AlgorithmSnafu, AuthenticodeSnafu, ParsePrivateKeySnafu, ParseCertificateSnafu, ParseImageSnafu, ReadBtyeSnafu, WriteBtyeSnafu, InvalidMagicInOptHdrSnafu, MissingOptHdrSnafu, OpenFileSnafu, PemFileSnafu, Result};

pub mod error;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub WinCertificate);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub offset: usize,
    pub data: Vec<u8>,
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
}

const CHECK_SUM_OFFSET: usize = 64; // offset from start of optional header to check sum filed
const SIZEOF_CHECKSUM: usize = mem::size_of::<u32>();
const CERT_TABLE_OFFSET: usize = 4 * mem::size_of::<DataDirectory>() as usize; // offset from start of data directories to cert table direcotory
const SIZEOF_CERT_TABLE: usize = mem::size_of::<DataDirectory>() as usize;

#[repr(C)]
pub struct WinCertHeader {
    length: u32,
    revision: u16,
    cert_type: u16,
}

impl<'a> EfiImage<'a> {
    pub fn get_pem_from_file(certfile_path: &PathBuf) -> Result<Pem<'a>> {
        let certfile = Pem::read_from(&mut BufReader::new(
            File::open(certfile_path.as_path()).context(OpenFileSnafu{path: certfile_path.as_path().display().to_string()})?
        )).context(PemFileSnafu {path: certfile_path.as_path().display().to_string()})?;

        Ok(certfile)
    }

    fn get_cert_table_addr(pe: &PE) -> Result<Option<DataDirectory>> {
        Ok(pe
            .header
            .optional_header
            .context(MissingOptHdrSnafu{})?
            .data_directories
            .get_certificate_table()
            .clone())
    }

    fn get_cert_table_section(pe: &PE, pe_raw: &[u8]) -> Result<Section> {
        let dd = EfiImage::get_cert_table_addr(pe)?
            .context(MissingOptHdrSnafu{})?;

        Ok(Section {
            offset: dd.virtual_address as usize,
            data: pe_raw[dd.virtual_address as usize..(dd.virtual_address + dd.size) as usize]
                .to_vec(),
        })
    }

    fn get_cert_table_offset(pe: &PE) -> Result<usize> {
        let hdr = pe.header.optional_header.context(MissingOptHdrSnafu{})?;
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
            _ => InvalidMagicInOptHdrSnafu{magic: hdr.standard_fields.magic}.fail()?,
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
        let checksum_offset = EfiImage::get_check_sum_offset(&pe);
        Ok(Section {
            offset: checksum_offset,
            data: pe_raw[checksum_offset..checksum_offset + mem::size_of::<u32>()].to_vec(),
        })
    }

    fn get_dd_offset(pe: &PE) -> Result<usize> {
        Ok(EfiImage::get_check_sum_offset(pe)
            + SIZEOF_CHECKSUM
            + EfiImage::get_cert_table_offset(&pe)?)
    }

    fn get_cert_dd_secion(pe: &PE, pe_raw: &[u8]) -> Result<Section> {
        let cert_dd_offset = EfiImage::get_dd_offset(pe)?;
        Ok(Section {
            offset: cert_dd_offset,
            data: pe_raw[cert_dd_offset..cert_dd_offset + SIZEOF_CERT_TABLE].to_vec(),
        })
    }

    fn check_sum(mut checksum: u32, data: &[u8], mut steps: usize) -> Result<u32> {
        if steps > 0 {
            let mut rdr = Cursor::new(data);
            let mut sum: u32;
            loop {
                sum = rdr.read_u16::<LittleEndian>().context(ReadBtyeSnafu{offset: rdr.position() as usize, size: mem::size_of::<u16>()})? as u32 + checksum;
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
        let hdr = pe.header.optional_header.context(MissingOptHdrSnafu{})?;
        let mut res: Vec<Section> = Vec::new();
        let file_size = pe_raw.len();
        let end_of_sections =
            EfiImage::get_section_size(&pe) + hdr.windows_fields.size_of_headers as usize;

        if file_size < end_of_sections {
            ParseImageSnafu{reason: "file size lesser than header_size + section_size, corrupt headers."}.fail()?
        }
        // no overlay
        if file_size == end_of_sections {
            return Ok(None);
        }
        // if we have a cert table
        if let Some(cert_dd) = EfiImage::get_cert_table_addr(pe)? {
            let overlay_offset =
                EfiImage::get_section_size(&pe) + hdr.windows_fields.size_of_headers as usize;
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

    pub fn do_sign_signature(
        file_hash: Vec<u8>,
        certfile: PathBuf,
        private_key: PathBuf,
        program_name: Option<String>,
    ) -> Result<Signature> {
        let key_pem = EfiImage::get_pem_from_file(&private_key)?;
        let cert_pem = EfiImage::get_pem_from_file(&certfile)?;

        let pkey = PrivateKey::from_pem(&key_pem)
            .context(ParsePrivateKeySnafu{path: private_key.clone().as_path().display().to_string()})?;
        let pkcs7 = Pkcs7::from_pem(&cert_pem)
            .context(ParseCertificateSnafu{path: certfile.clone().as_path().display().to_string()})?;

        let authenticode_signature = AuthenticodeSignature::new(
            &pkcs7,
            file_hash.to_vec(),
            ShaVariant::SHA2_256,
            &pkey,
            program_name,
        )
        .context(AuthenticodeSnafu{})?;

        let raw_authenticode_signature =
            authenticode_signature.to_der().context(AuthenticodeSnafu {})?;
        debug!("a new signature created, size: {:#04x}", raw_authenticode_signature.len());
        let wincert = WinCertificate::from_certificate(
            raw_authenticode_signature,
            CertificateType::WinCertTypePkcsSignedData,
        );

        Ok(Signature(wincert))
    }

    pub fn get_digest_algo(&self) -> Result<Option<ShaVariant>> {
        match self.signatures.len() {
            0 => Ok(None),
            _ => {
                let code = AuthenticodeSignature::from_der(&self.signatures[0].0.get_certificate())
                    .context(AuthenticodeSnafu{})?;
                Ok(Some(
                    ShaVariant::try_from(code.0.digest_algorithms()[0].oid_asn1().clone()) 
                        .context(AlgorithmSnafu{})?,
                ))
            }
        }
    }

    fn parse_cert_table(
        pe: &PE,
        raw: &'a [u8],
    ) -> Result<(Vec<Signature>, Option<Section>)> {
        let mut res: Vec<Signature> = Vec::new();
        let mut rdr = Cursor::new(raw);
        let mut cert_table = None;

        if let Some(cert_table_addr) = EfiImage::get_cert_table_addr(pe)? {
            rdr.set_position(cert_table_addr.virtual_address as u64);
            let mut begin = cert_table_addr.virtual_address as usize;

            cert_table = Some(EfiImage::get_cert_table_section(pe, raw)?);
            // there maybe more than one signature
            // so we scan over all the cert table
            while rdr
                .has_data_left()
                .context(ReadLeftDataSnafu{})?
            {
                // “length” indicating the length of the structure, include the header itself
                // so the length of the signed data should be length - 4 - 2 - 2
                let length = rdr
                    .read_u32::<LittleEndian>()
                    .context(ReadBtyeSnafu{offset: rdr.position() as usize, size: mem::size_of::<u32>()})?;

                // grab the signed-data directly from buffer
                // and move the position forward
                let mut sd_end = begin + length as usize;

                let cert_data = &raw[begin..sd_end];
                let wincert = WinCertificate::decode(cert_data)
                    .context(WinCertSnafu{})?;
                let code = AuthenticodeSignature::from_der(wincert.get_certificate())
                    .context(AuthenticodeSnafu{})?;
                //authenticode only contains one digest algorithm
                if code.0.digest_algorithms().len() != 1 {
                    ParseImageSnafu{ reason: format!(
                        "invalid digest algorithms numbers: {}",
                        code.0.digest_algorithms().len()
                    )}.fail()?
                }

                if code.0.signer_infos().len() != 1 {
                    ParseImageSnafu{ reason: format!(
                        "invalid signer_info numbers: {}",
                        code.0.signer_infos().len()
                    )}.fail()?
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

    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        let pe = Box::new(PE::parse(buf).context(PESnafu{})?);
        let mut rdr = Cursor::new(buf);

        rdr.set_position(pe.header.dos_header.pe_pointer as u64);
        let signature = rdr
            .read_u32::<LittleEndian>()
            .context(ReadBtyeSnafu{offset: rdr.position() as usize, size: mem::size_of::<u32>()})?;
        if signature != PE_MAGIC {
            ParseImageSnafu{ reason: format!(
                "pe magic check failed expect:{} actual:{}",
                PE_MAGIC,
                signature
            )}.fail()?
        }
        let (res, cert_table) = EfiImage::parse_cert_table(&pe, buf)?;

        let checksum = EfiImage::get_check_sum_section(&pe, buf)?;

        let cert_dd = EfiImage::get_cert_dd_secion(&pe, buf)?;

        let overlay = EfiImage::get_overlay_section(&pe, buf)?;

        let mut raw = buf.to_vec();
        // add some padding to end of the file so that the file size is byte aligned
        if raw.len() % 8 != 0 {
            let padding = (raw.len() / 8 + 1 ) * 8 - raw.len();
            debug!("zero-pad {} bytes", padding);
            raw.append(&mut vec![0u8; padding]);
        }
        Ok(EfiImage {
            pe: pe,
            raw: raw,
            cert_data_directory: cert_dd,
            checksum: checksum,
            cert_table: cert_table,
            overlay: overlay,
            signatures: res,
        })
    }

    pub fn get_checksum_from_header(&self) -> Result<u32> {
        let mut rdr = Cursor::new(&self.raw);
        rdr.set_position(self.checksum.offset as u64);
        Ok(rdr
            .read_u32::<LittleEndian>()
            .context(ReadBtyeSnafu{offset: rdr.position() as usize, size: mem::size_of::<u32>()})?)
    }
    // get digest from EFI image
    pub fn get_digest(&self) -> Result<Option<Vec<u8>>> {
        let mut hashes = Vec::new();
        for sig in self.signatures.iter() {
            let code = AuthenticodeSignature::from_der(sig.0.get_certificate())
                    .context(AuthenticodeSnafu{})?;
            let Some(hash) = code.file_hash() else {
                continue;
            };

            if hashes.len() != 0 && hash != hashes[0] {
                ParseImageSnafu{ reason: format!("signature with different hash {:x?} and {:x?}", hash, hash[0])}.fail()?
            }

            hashes.push(hash);
        }
        match hashes.len() {
            0 => Ok(None),
            _ => Ok(Some(hashes[0].clone())),
        }
    }

    // follow the calculating the pe image hash guard in authenticode spec:
    // checksum, certificate table data directory and attribute certificate table are excluded from the whole header
    // all sections are included by sorting ASC order by PointerToRawData
    // the data remain behind certificate table also included
    pub fn compute_digest(&self, alg: ShaVariant) -> Result<Vec<u8>> {
        let hdr = self.pe.header.optional_header.context(MissingOptHdrSnafu{})?;

        let mut hasher: Box<dyn DynDigest> = match alg {
            ShaVariant::MD5 => Box::new(md5::Md5::default()),
            ShaVariant::SHA1 => Box::new(sha1::Sha1::default()),
            ShaVariant::SHA2_256 => Box::new(sha2::Sha256::default()),
            _ => ComputeDigestSnafu{reason: format!("not supported digest method: {:?}", alg)}.fail()?
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
            debug!("hashed from [{:#04x} - {:#04x}]", sec.pointer_to_raw_data, sec.pointer_to_raw_data + sec.size_of_raw_data);
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
                debug!("hashed from [{:#04x} - {:#04x}]", sum_of_bytes_hashed, dd.virtual_address );
                hasher.update(&self.raw[sum_of_bytes_hashed as usize..dd.virtual_address as usize]);
                debug!("hashed from [{:#04x} - {:#04x}]", dd.virtual_address + dd.size, file_size);
                hasher.update(&self.raw[(dd.virtual_address + dd.size) as usize..]);
            } else {
                debug!("hashed from [{:#04x} - {:#04x}]", sum_of_bytes_hashed, file_size);
                hasher.update(&self.raw[sum_of_bytes_hashed as usize..]);
            }
        }

        Ok(hasher.finalize().to_vec())
    }

    pub fn get_pe_ref(&self) -> &Box<PE> {
        &self.pe
    }
    // reference: https://www.cnblogs.com/concurrency/p/3926698.html
    // notice: call this method need flush self.raw first
    pub fn compute_check_sum(&self) -> Result<u32> {
        let file_size = self.raw.len();
        let checksum_offset = EfiImage::get_check_sum_offset(&self.pe);
        let checksum_steps = checksum_offset >> 1;
        let checksum_after_size = (file_size - checksum_offset - 4) >> 1;
        let checksum_after_offset = checksum_offset + 4;

        let mut checksum = EfiImage::check_sum(0, &self.raw[..checksum_offset], checksum_steps)?;
        checksum = EfiImage::check_sum(
            checksum,
            &self.raw[checksum_after_offset..],
            checksum_after_size,
        )?;

        if file_size & 1 > 0 {
            checksum += self.raw[file_size - 1] as u32;
        }

        Ok(file_size as u32 + checksum)
    }

    // embedded signatures into the image
    pub fn set_authenticode(&self, signatures: Vec<Signature>) -> Result<Vec<u8>> {
        let hdr = self.pe.header.optional_header.context(MissingOptHdrSnafu{})?;
        let mut res: Vec<u8>;
        let mut size: u32 = 0;
        let rva: u32;
        // already contain a signature, just append
        if let Some(dd) = hdr.data_directories.data_directories[4] {
            let mut end_of_signature: u32 = dd.virtual_address + dd.size;
            rva = dd.virtual_address;
            size = dd.size;
            debug!("already has some signatures, old rva and size: {:#04x}/{:#04x}", rva, size);
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
                let mut code_raw = sig.0.clone().encode().context(WinCertSnafu{})?;
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
                    debug!("append second overlay buffer from [{:#04x} - {:#04x}]", s[1].offset, s[1].offset + s[1].data.len());
                    res.append(&mut s[1].data.clone());
                    size += s[1].data.len() as u32;
                }
            }
        } else {
            debug!("no signatures before, add a new signature");
            // no signatures existed, just append to the end of the file
            res = self.raw.clone();
            rva = res
                .len() as u32;

            for sig in signatures.iter() {
                let mut padding :usize = 0;
                let mut tmp = sig.0.clone().encode().context(WinCertSnafu{})?;
                debug!("append new signature, size: {:#04x}", tmp.len());

                size += tmp.len() as u32;
                res.append(&mut tmp);
                // append some padding
                if tmp.len() % 8 != 0 {
                    padding = (tmp.len() / 8 + 1) * 8 - tmp.len();
                }
                size += padding as u32;
                res.append(&mut vec![0u8; padding as usize]);
            }
        }
        debug!("new rva and size: {:#04x}/{:#04x}", rva, size);

        let dd_offset = EfiImage::get_dd_offset(&self.pe)?;
        // insert the data directory into origin pe
        let mut writer :Vec<u8> = Vec::new();

        writer
            .write_u32::<LittleEndian>(rva)
            .context(WriteBtyeSnafu{offset: writer.len() as usize, size: mem::size_of::<u32>()})?;
        writer
            .write_u32::<LittleEndian>(size)
            .context(WriteBtyeSnafu{offset: writer.len() as usize, size: mem::size_of::<u32>()})?;
        res.splice(dd_offset..(dd_offset + SIZEOF_DATA_DIRECTORY), writer.iter().cloned());
        debug!("new image total size: {:#04x}", res.len());
        Ok(res)
    }

    // how to verify a signature against its binary
    // refer from microsoft authenticode_pe.docx
    pub fn verify(&self) -> Result<()> {
        // extracting and verify pkcs #7
        // certificate processing
        // timestamp processing
        //calculating the PE image hash
        let now = UtcDate::now();
        let file_hash = self.compute_digest(self.get_digest_algo()?.context(NoDigestAlgoSnafu{})?)?;
        for sig in self.signatures.iter() {
            let code = AuthenticodeSignature::from_der(&sig.0.get_certificate())
                    .context(AuthenticodeSnafu{})?;
            let verfier: picky::x509::pkcs7::authenticode::AuthenticodeValidator = code.authenticode_verifier();
            verfier.require_basic_authenticode_validation(file_hash.clone())
            .require_not_after_check()
            .require_not_before_check()
            .exact_date(&now)
            .ignore_chain_check()
            .ignore_ca_against_ctl_check(); // we just ignore ctl check as picky not support set a user provided cert as trust anchor
            verfier.verify().context(AuthenticodeSnafu{})?;
        }

        Ok(())
    }

    pub fn sign_signature(
        &self,
        certfile: PathBuf,
        private_key: PathBuf,
        program_name: Option<String>,
        mut algo: ShaVariant,
    ) -> Result<Vec<u8>> {
        if let Some(a) = self.get_digest_algo()? {
            warn!("a digest algorithm:{:?} already existed, ignore input args {:?}", a, algo);
            algo = a;
        }
        let file_hash = self.compute_digest(algo)?;

        let signature =
            EfiImage::do_sign_signature(file_hash.to_vec(), certfile, private_key, program_name)?;
        Ok(self.set_authenticode(vec![signature])?)
    }

    pub fn print_info(&self) -> Result<()> {
        debug!("EFI image info:");
        debug!("calculated sha256 {:x?}", self.compute_digest(picky::x509::pkcs7::authenticode::ShaVariant::SHA2_256)?);
        debug!("embedded sha256 digest {:x?}", self.get_digest());
        debug!("checksum {:#06x}", self.compute_check_sum()?);
        if let Some(ref o) = self.overlay {
            let mut tot_size = 0;
            for s in o.iter() {
                debug!("overlay from [{:#06x} - {:#06x}] size {:#06x}", s.offset, s.offset + s.data.len(), s.data.len());
                tot_size += s.data.len();
            }
            debug!("section total size: {:#04x}", tot_size);
        }
        if let Some(ref c) = self.cert_table {
            debug!("the attribute certificate table: [{:#06x} - {:#06x}]", c.offset, c.offset + c.data.len());
        }

        let hdr = self.pe.header.optional_header.context(MissingOptHdrSnafu{})?;
        if let Some(dd) = hdr.data_directories.data_directories[4] {
            debug!("pe the certificate data info: [{:#06x} - {:#06x}]", dd.virtual_address, dd.virtual_address+dd.size);
        }

        if let Some(algo) = self.get_digest_algo()? {
            debug!("digest algo: {:?}", algo);
        }
        Ok(())
    }
}
