# EFI_SIGNER
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
./main sign --key key.pem --cert certificate.pem shimx64.efi shimx64.efi.signed
```

## how to parse the EFI image
```bash
./main --verbose parse shimx64.efi
```