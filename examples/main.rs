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
use clap::{Args, Parser, Subcommand};
use efi_signer::DigestAlgorithm;
use log::debug;
use std::env;
use std::fs::read;
use std::io::Write;
use std::path::PathBuf;
use std::str;
use std::str::FromStr;

#[derive(Parser)]
#[command(name = "efi_signer examples")]
#[command(author = "Li chaoran <pkwarcraft@gmail.com>")]
#[command(version = "0.10")]
#[command(about = "Sign the EFI image", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long)]
    #[arg(help = "Print more info")]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Sign a EFI image with key and cert", long_about = None)]
    Sign(Sign),
    #[command(about = "Parse a EFI image", long_about = None)]
    Parse(Parse),
    #[command(about = "Convert pem to p7b", long_about = None)]
    P7b(P7b),
}

#[derive(Args)]
struct P7b {
    #[arg(short, long, action(clap::ArgAction::Append))]
    #[arg(help = "PEM certs to convert")]
    cert: Option<Vec<String>>,
    #[arg(help = "PKCS7 output file path")]
    output: String,
}

#[derive(Args)]
struct Parse {
    #[arg(help = "EFI image path to parse")]
    path: String,
    #[arg(short, long, action(clap::ArgAction::Append))]
    #[arg(help = "Certificate to verify the signatures in the EFI image")]
    certs: Option<Vec<String>>,
}

#[derive(Args)]
struct Sign {
    #[arg(long, short, required(true))]
    #[arg(help = "Private key in PEM format")]
    key: String,
    #[arg(long, short, required(true))]
    #[arg(help = "Certificate in pkcs7 format")]
    cert: String,
    #[arg(long, short, required(false))]
    #[arg(help = "Whether to generate a detach signature")]
    detach: bool,
    #[arg(help = "EFI image path to sign")]
    path: String,
    #[arg(help = "Signed EFI image path")]
    output: String,
}

fn p7b(paths: Vec<String>, output: &str) {
    let mut bufs: Vec<Vec<u8>> = vec![];
    for path in paths.iter() {
        let pem_file_content = read(path).unwrap();

        debug!("read cert: {}", path);
        bufs.push(pem_file_content);
    }
    let p7 = efi_signer::EfiImage::pems_to_p7(bufs).unwrap();

    let mut file = std::fs::File::create(output).unwrap();
    file.write_all(&p7).unwrap();
}

fn sign(path: &str, output: &str, key: &str, cert: &str, detach: bool) {
    let buf = read(path).unwrap();
    let pe = efi_signer::EfiImage::parse(&buf).unwrap();

    pe.print_info().unwrap();

    if detach {
        let key_pem = read(key).unwrap();
        let cert_pem = read(cert).unwrap();

        let file_hash = pe.compute_digest(DigestAlgorithm::Sha256).unwrap();

        let signature = efi_signer::EfiImage::do_sign_signature(
            file_hash.to_vec(),
            cert_pem,
            key_pem,
            None,
            DigestAlgorithm::Sha256,
        )
        .unwrap();

        let mut f = std::fs::File::create(output).unwrap();
        f.write_all(&signature.encode().unwrap()).unwrap();

        return;
    }

    let sig = pe
        .sign_signature(
            PathBuf::from_str(cert).unwrap(),
            PathBuf::from_str(key).unwrap(),
            None,
            DigestAlgorithm::Sha256,
        )
        .unwrap();

    let new_pe = efi_signer::EfiImage::parse(&sig).unwrap();

    new_pe.print_info().unwrap();

    let mut file = std::fs::File::create(output).unwrap();

    file.write_all(&sig).unwrap();
}

fn parse(path: &str, certs: Option<Vec<String>>) {
    let buf = read(path).unwrap();
    let pe = efi_signer::EfiImage::parse(&buf).unwrap();

    if let Some(paths) = certs {
        match pe.verify(paths) {
            Ok(_) => println!("verify: Ok"),
            Err(e) => println!("verify: Failed(reason: {})", e),
        }
    }
    pe.print_info().unwrap();
}

fn main() {
    //prepare config and logger
    let app = Cli::parse();
    if app.verbose {
        println!("debug enabled");
        env::set_var("RUST_LOG", "debug");
    }
    env_logger::init();

    match app.command {
        Commands::Parse(p) => parse(&p.path, p.certs),
        Commands::Sign(s) => sign(&s.path, &s.output, &s.key, &s.cert, s.detach),
        Commands::P7b(p) => p7b(p.cert.unwrap(), &p.output),
    }
}
