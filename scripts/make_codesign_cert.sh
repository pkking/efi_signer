#!/bin/bash -e

# a example to describe how to generate a code sign certificate
# please note: the picky hardcode the sign algo to ras_with_sha, so we can only generate rsa key/cert
# output:
#  privatekey: key.pem
#  certificate: certificate.p7b
set -o pipefail
[ `which openssl 2>/dev/null` ] || (echo "please install openssl firstly"; exit 1)

# generate a rsa key
openssl genrsa -out ca.key 4096
# generate a csr for rootca
openssl req -new -sha256 -key ca.key -out ca.csr -subj '/CN=efiRoot/C=CN/OU=openEuler/O=infra'
# sign the rootca
openssl req -x509 -sha256 -days 3650 -key ca.key -in ca.csr -out rootca.pem -subj '/CN=efiRoot/C=CN/OU=openEuler/O=infra'
# generate a sign cert
# key first
openssl genrsa -out signer.key 4096
# csr for sign cert
openssl req -new -sha256 -key signer.key -out signer.csr -subj '/CN=efiSigner/C=CN/OU=openEuler/O=infra'
# sign
openssl x509 -req -in signer.csr -CA rootca.pem -CAkey ca.key -CAcreateserial -out signer.pem
# convert x509 to pkcs7
openssl crl2pkcs7 -nocrl -certfile signer.pem -out signer.p7b

