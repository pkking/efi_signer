#!/bin/bash -e

# a example to describe how to generate a code sign certificate
# please note: the picky hardcodes the sign algo to rsa_with_sha, so we can only generate rsa key/cert
# output:
#  privatekey: key.pem
#  certificate: certificate.p7b
set -o pipefail
[ `which openssl 2>/dev/null` ] || (echo "please install openssl firstly"; exit 1)

# generate a ecc key
openssl genrsa -out key.pem 4096
# generate a csr
openssl req -new -sha256 -key key.pem -out csr.csr -subj '/CN=efiSigner/C=CN/OU=openEuler/O=infra'
# sign a certificate
openssl req -x509 -sha256 -days 365 -key key.pem -in csr.csr -out certificate.pem -subj '/CN=efiSigner/C=CN/OU=openEuler/O=infra' -addext "extendedKeyUsage = 1.3.6.1.5.5.7.3.3"
# convert x509 to pkcs7
openssl crl2pkcs7 -nocrl -certfile certificate.pem -out certificate.p7b
