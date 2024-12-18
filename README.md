# EFI_SIGNER
[![Coverage Status](https://img.shields.io/coverallsCoverage/github/pkking/efi_signer?style=flat-square)](https://img.shields.io/coverallsCoverage/github/pkking/efi_signer?style=flat-square)
[![cargo](https://img.shields.io/crates/d/efi_signer?style=flat-square)](https://img.shields.io/crates/d/efi_signer?style=flat-square)
[![license](https://img.shields.io/crates/l/efi_signer?style=flat-square)](https://img.shields.io/crates/l/efi_signer?style=flat-square)
[![](https://img.shields.io/crates/v/efi_signer?style=flat-square)](https://img.shields.io/crates/v/efi_signer?style=flat-square)
[![](https://img.shields.io/docsrs/efi_signer?style=flat-square)](https://img.shields.io/docsrs/efi_signer?style=flat-square)

A pure rust library to sign/verify the EFI image.

# HOWs
see [examples](./examples/main.rs)

## how to sign a EFI image
1. generate certificates
    ```bash
    bash -ex scripts/make_codesign_cert.sh
    ```

1. sign a EFI image
    ```bash
    ./main sign --key key.pem --cert certificate.p7b shimx64.efi shimx64.efi.signed
    ```

1. sign a EFI image with detached signature
    ```bash
    ./main sign --key key.pem --cert certificate.p7b -d shimx64.efi efi.signed
    ```
    the `efi.signed` file will onlyl contain the signature itself which can be used by [set_authenticode](https://docs.rs/efi_signer/latest/efi_signer/struct.EfiImage.html#method.set_authenticode)
## how to parse the EFI image
```bash
./main --verbose parse shimx64.efi
```