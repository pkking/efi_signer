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
use clap::{Parser, Subcommand, Args};
use std::fs::read;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::env;

#[derive(Parser)]
#[command(name = "efi_signer examples")]
#[command(author = "Li chaoran <pkwarcraft@gmail.com>")]
#[command(version = "0.10")]
#[command(about = "Sign the EFI image", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long)]
    #[arg(help = "print more info")]
    verbose: bool
}

#[derive(Args)]
struct CliArgs {
    #[arg(short, long)]
    #[arg(help = "print more info")]
    verbose: bool
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Sign a EFI image with key and cert", long_about = None)]
    Sign(Sign),
    #[command(about = "Parse a EFI image", long_about = None)]
    Parse(Parse),
}


#[derive(Args)]
struct Parse {
    #[arg(long)]
    #[arg(help = "whether to verify the image")]
    verify: bool,
    #[arg(help = "EFI image path to parse")]
    path: String,
}


#[derive(Args)]
struct Sign {
    #[arg(long, short, required(true))]
    #[arg(help = "private key in pem format")]
    key: String,
    #[arg(long, short, required(true))]
    #[arg(help = "certificate in pem format")]
    cert: String,
    #[arg(help = "EFI image path to sign")]
    path: String,
    #[arg(help = "EFI image path to sign")]
    output: String,
}

fn sign(path :&str, output :&str, key :&str, cert :&str) {
    let buf = read(path).unwrap();
    let pe = efi_signer::EfiImage::parse(&buf).unwrap();

    pe.print_info().unwrap();

    let sig = pe.sign_signature(PathBuf::from_str(cert).unwrap(), PathBuf::from_str(key).unwrap(), None, picky_asn1_x509::ShaVariant::SHA2_256).unwrap();

    let new_pe = efi_signer::EfiImage::parse(&sig).unwrap();

    new_pe.print_info().unwrap();

    let mut file = std::fs::File::create(output).unwrap();

    file.write_all(&sig).unwrap();
}

fn parse(path :&str, verify :bool) {
    let buf = read(path).unwrap();
    let pe = efi_signer::EfiImage::parse(&buf).unwrap();

    pe.print_info().unwrap();

    if verify {
        pe.verify().unwrap();
    }
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
        Commands::Parse(p) => parse(&p.path, p.verify),
        Commands::Sign(s) => sign(&s.path, &s.output, &s.key ,&s.cert),
    }
}
